/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2011, Lawrence Livermore National Security, LLC.
 */


#include <sys/zfs_vfsops.h>
#include <sys/zfs_vnops.h>
#include <sys/zfs_znode.h>
#include <sys/vfs.h>
#include <sys/zpl.h>
#include <sys/acl.h>


static struct dentry *
#ifdef HAVE_LOOKUP_NAMEIDATA
zpl_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd)
#else
zpl_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
#endif
{
	cred_t *cr = CRED();
	struct inode *ip;
	int error;

	crhold(cr);
	error = -zfs_lookup(dir, dname(dentry), &ip, 0, cr, NULL, NULL);
	ASSERT3S(error, <=, 0);
	crfree(cr);

	if (error) {
		if (error == -ENOENT)
			return d_splice_alias(NULL, dentry);
		else
			return ERR_PTR(error);
	}

	return d_splice_alias(ip, dentry);
}

void
zpl_vap_init(vattr_t *vap, struct inode *dir, struct dentry *dentry,
    zpl_umode_t mode, cred_t *cr)
{
	vap->va_mask = ATTR_MODE;
	vap->va_mode = mode;
	vap->va_dentry = dentry;
	vap->va_uid = crgetfsuid(cr);

	if (dir && dir->i_mode & S_ISGID) {
		vap->va_gid = dir->i_gid;
		if (S_ISDIR(mode))
			vap->va_mode |= S_ISGID;
	} else {
		vap->va_gid = crgetfsgid(cr);
	}
}

static int
#ifdef HAVE_CREATE_NAMEIDATA
zpl_create(struct inode *dir, struct dentry *dentry, zpl_umode_t mode,
    struct nameidata *nd)
#else
zpl_create(struct inode *dir, struct dentry *dentry, zpl_umode_t mode,
    bool flag)
#endif
{
	cred_t *cr = CRED();
	struct inode *ip;
	vattr_t *vap;
	int error;

	crhold(cr);
	vap = kmem_zalloc(sizeof(vattr_t), KM_SLEEP);
	zpl_vap_init(vap, dir, dentry, mode, cr);

	error = -zfs_create(dir, (char *)dentry->d_name.name,
	    vap, 0, mode, &ip, cr, 0, NULL);
	kmem_free(vap, sizeof(vattr_t));
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

static int
zpl_mknod(struct inode *dir, struct dentry *dentry, zpl_umode_t mode,
    dev_t rdev)
{
	cred_t *cr = CRED();
	struct inode *ip;
	vattr_t *vap;
	int error;

	/*
	 * We currently expect Linux to supply rdev=0 for all sockets
	 * and fifos, but we want to know if this behavior ever changes.
	 */
	if (S_ISSOCK(mode) || S_ISFIFO(mode))
		ASSERT(rdev == 0);

	crhold(cr);
	vap = kmem_zalloc(sizeof(vattr_t), KM_SLEEP);
	zpl_vap_init(vap, dir, dentry, mode, cr);
	vap->va_rdev = rdev;

	error = -zfs_create(dir, (char *)dentry->d_name.name,
	    vap, 0, mode, &ip, cr, 0, NULL);
	kmem_free(vap, sizeof(vattr_t));
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (-error);
}

static int
zpl_unlink(struct inode *dir, struct dentry *dentry)
{
	cred_t *cr = CRED();
	int error;

	crhold(cr);
	error = -zfs_remove(dir, dname(dentry), cr);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

static int
zpl_mkdir(struct inode *dir, struct dentry *dentry, zpl_umode_t mode)
{
	cred_t *cr = CRED();
	vattr_t *vap;
	struct inode *ip;
	int error;

	crhold(cr);
	vap = kmem_zalloc(sizeof(vattr_t), KM_SLEEP);
	zpl_vap_init(vap, dir, dentry, mode | S_IFDIR, cr);

	error = -zfs_mkdir(dir, dname(dentry), vap, &ip, cr, 0, NULL);
	kmem_free(vap, sizeof(vattr_t));
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

static int
zpl_rmdir(struct inode * dir, struct dentry *dentry)
{
	cred_t *cr = CRED();
	int error;

	crhold(cr);
	error = -zfs_rmdir(dir, dname(dentry), NULL, cr, 0);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

static int
zpl_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	boolean_t issnap = ITOZSB(dentry->d_inode)->z_issnap;
	int error;

	/*
	 * Ensure MNT_SHRINKABLE is set on snapshots to ensure they are
	 * unmounted automatically with the parent file system.  This
	 * is done on the first getattr because it's not easy to get the
	 * vfsmount structure at mount time.  This call path is explicitly
	 * marked unlikely to avoid any performance impact.  FWIW, ext4
	 * resorts to a similar trick for sysadmin convenience.
	 */
	if (unlikely(issnap && !(mnt->mnt_flags & MNT_SHRINKABLE)))
		mnt->mnt_flags |= MNT_SHRINKABLE;

	error = -zfs_getattr_fast(dentry->d_inode, stat);
	ASSERT3S(error, <=, 0);

	return (error);
}

static int
zpl_setattr(struct dentry *dentry, struct iattr *ia)
{
	cred_t *cr = CRED();
	vattr_t *vap;
	int error;

	error = inode_change_ok(dentry->d_inode, ia);
	if (error)
		return (error);

	crhold(cr);
	vap = kmem_zalloc(sizeof(vattr_t), KM_SLEEP);
	vap->va_mask = ia->ia_valid & ATTR_IATTR_MASK;
	vap->va_mode = ia->ia_mode;
	vap->va_uid = ia->ia_uid;
	vap->va_gid = ia->ia_gid;
	vap->va_size = ia->ia_size;
	vap->va_atime = ia->ia_atime;
	vap->va_mtime = ia->ia_mtime;
	vap->va_ctime = ia->ia_ctime;

	error = -zfs_setattr(dentry->d_inode, vap, 0, cr);

	kmem_free(vap, sizeof(vattr_t));
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

static int
zpl_rename(struct inode *sdip, struct dentry *sdentry,
    struct inode *tdip, struct dentry *tdentry)
{
	cred_t *cr = CRED();
	int error;

	crhold(cr);
	error = -zfs_rename(sdip, dname(sdentry), tdip, dname(tdentry), cr, 0);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

static int
zpl_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
	cred_t *cr = CRED();
	vattr_t *vap;
	struct inode *ip;
	int error;

	crhold(cr);
	vap = kmem_zalloc(sizeof(vattr_t), KM_SLEEP);
	zpl_vap_init(vap, dir, dentry, S_IFLNK | S_IRWXUGO, cr);

	error = -zfs_symlink(dir, dname(dentry), vap, (char *)name, &ip, cr, 0);
	kmem_free(vap, sizeof(vattr_t));
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

static void *
zpl_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	cred_t *cr = CRED();
	struct inode *ip = dentry->d_inode;
	struct iovec iov;
	uio_t uio;
	char *link;
	int error;

	crhold(cr);

	iov.iov_len = MAXPATHLEN;
	iov.iov_base = link = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = (MAXPATHLEN - 1);
	uio.uio_segflg = UIO_SYSSPACE;

	error = -zfs_readlink(ip, &uio, cr);
	if (error) {
		kmem_free(link, MAXPATHLEN);
		nd_set_link(nd, ERR_PTR(error));
	} else {
		nd_set_link(nd, link);
	}

	crfree(cr);
	return (NULL);
}

static void
zpl_put_link(struct dentry *dentry, struct nameidata *nd, void *ptr)
{
	const char *link = nd_get_link(nd);

	if (!IS_ERR(link))
		kmem_free(link, MAXPATHLEN);
}

static int
zpl_link(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry)
{
	cred_t *cr = CRED();
	struct inode *ip = old_dentry->d_inode;
	int error;

	if (ip->i_nlink >= ZFS_LINK_MAX)
		return -EMLINK;

	crhold(cr);
	ip->i_ctime = CURRENT_TIME_SEC;
	igrab(ip); /* Use ihold() if available */

	error = -zfs_link(dir, ip, dname(dentry), cr);
	if (error) {
		iput(ip);
		goto out;
	}

	d_instantiate(dentry, ip);
out:
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

#ifdef HAVE_INODE_TRUNCATE_RANGE
static void
zpl_truncate_range(struct inode* ip, loff_t start, loff_t end)
{
	cred_t *cr = CRED();
	flock64_t bf;

	ASSERT3S(start, <=, end);

	/*
	 * zfs_freesp() will interpret (len == 0) as meaning "truncate until
	 * the end of the file". We don't want that.
	 */
	if (start == end)
		return;

	crhold(cr);

	bf.l_type = F_WRLCK;
	bf.l_whence = 0;
	bf.l_start = start;
	bf.l_len = end - start;
	bf.l_pid = 0;
	zfs_space(ip, F_FREESP, &bf, FWRITE, start, cr);

	crfree(cr);
}
#endif /* HAVE_INODE_TRUNCATE_RANGE */

#ifdef HAVE_INODE_FALLOCATE
static long
zpl_fallocate(struct inode *ip, int mode, loff_t offset, loff_t len)
{
	return zpl_fallocate_common(ip, mode, offset, len);
}
#endif /* HAVE_INODE_FALLOCATE */


static int zpl_permission(struct inode* ino, int mask){
	int error = 0;
	cred_t *cr = CRED();
	crhold(cr);
	if(mask & MAY_READ){
		error=-zfs_access(ino,ACE_READ_DATA,V_ACE_MASK,cr);
		printk("MAY_READ,%i",error);
		if(error) goto end;
	}
	if(mask & MAY_WRITE){
		error=-zfs_access(ino,ACE_WRITE_DATA,V_ACE_MASK,cr);
		printk("MAY_WRITE,%i",error);
		if(error) goto end;
	}
	if(mask & MAY_EXEC){
		error=-zfs_access(ino,ACE_EXECUTE,V_ACE_MASK,cr);
		printk("MAY_EXEC,%i",error);
		if(error) goto end;
	}
	end:
	printk("mask=%i,error=%i\n",mask,error);
	crfree(cr);
	return (error);
}

const struct inode_operations zpl_inode_operations = {
	.create		= zpl_create,
	.link		= zpl_link,
	.unlink		= zpl_unlink,
	.symlink	= zpl_symlink,
	.mkdir		= zpl_mkdir,
	.rmdir		= zpl_rmdir,
	.mknod		= zpl_mknod,
	.rename		= zpl_rename,
	.setattr	= zpl_setattr,
	.getattr	= zpl_getattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.removexattr	= generic_removexattr,
	.listxattr	= zpl_xattr_list,
	.permission	= zpl_permission,
#ifdef HAVE_INODE_TRUNCATE_RANGE
	.truncate_range = zpl_truncate_range,
#endif /* HAVE_INODE_TRUNCATE_RANGE */
#ifdef HAVE_INODE_FALLOCATE
	.fallocate	= zpl_fallocate,
#endif /* HAVE_INODE_FALLOCATE */
};

const struct inode_operations zpl_dir_inode_operations = {
	.create		= zpl_create,
	.lookup		= zpl_lookup,
	.link		= zpl_link,
	.unlink		= zpl_unlink,
	.symlink	= zpl_symlink,
	.mkdir		= zpl_mkdir,
	.rmdir		= zpl_rmdir,
	.mknod		= zpl_mknod,
	.rename		= zpl_rename,
	.setattr	= zpl_setattr,
	.getattr	= zpl_getattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.removexattr	= generic_removexattr,
	.listxattr	= zpl_xattr_list,
	.permission	= zpl_permission,
};

const struct inode_operations zpl_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= zpl_follow_link,
	.put_link	= zpl_put_link,
	.setattr	= zpl_setattr,
	.getattr	= zpl_getattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.removexattr	= generic_removexattr,
	.listxattr	= zpl_xattr_list,
	.permission	= zpl_permission,
};

const struct inode_operations zpl_special_inode_operations = {
	.setattr	= zpl_setattr,
	.getattr	= zpl_getattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.removexattr	= generic_removexattr,
	.listxattr	= zpl_xattr_list,
	.permission	= zpl_permission,
};
