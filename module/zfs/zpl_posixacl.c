#include <linux/version.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_vnops.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_acl.h>
#include <sys/unistd.h>
#include "sys/vfs.h"
#include "sys/zpl.h"
#include "sys/zpl_posixacl.h"
#include "acl_common.h"
static int
__zpl_xattr_acl_get(struct inode *ip, const char *name,
                    void *value, size_t size,int type) {
    vsecattr_t sa;
    cred_t *cr;
    int err;
    acl_t * readacl;
    printk("posix acl get. type=%i\n",type);
    sa.vsa_mask=VSA_ACE|VSA_ACECNT|VSA_ACE_ACLFLAGS|VSA_ACE_ALLTYPES;
    cr=CRED();
    crhold(cr);
    err=zfs_getacl(ITOZ(ip),&sa,FALSE,cr);
    crfree(cr);
         printk("getfacl retvalue=%i\n",err);
        if(err) {
            return -err;
        }

 readacl=acl_alloc(ACE_T);
    readacl->acl_cnt=	sa.vsa_aclcnt;
    readacl->acl_aclp=	sa.vsa_aclentp;
    readacl->acl_entry_size=	sa.vsa_aclentsz;
	 printk("acl_type before:%i,cnt=%i\n",readacl->acl_type,readacl->acl_cnt);
        err=acl_translate(readacl,_ACL_ACLENT_ENABLED,S_ISDIR(ip->i_mode),ip->i_uid,ip->i_gid);
        printk("acl_type after:%i,cnt=%i\n",readacl->acl_type,readacl->acl_cnt);
        printk("translation:%i\n",err);
     
    acl_free(readacl);
    return -ENODATA;
}


static int
__zpl_xattr_acl_set(struct inode *ip, const char *name,
                    const void *value, size_t size, int flags,int type) {
    struct posix_acl * acl = NULL;
    struct posix_acl_entry *pa,*pe;
    vsecattr_t sa;
    acl_t* newacl=NULL;
    int err = 0;
    aclent_t* ptr;
    int flgs=0;
    unsigned long sz=0;
    cred_t *cr;
    printk("posix acl set. type=%i\n",type);
    if ((type != ACL_TYPE_ACCESS) && (type != ACL_TYPE_DEFAULT)) {
        return -EINVAL;
    }
    if (!inode_owner_or_capable(ip)) {
        return -EPERM;
    }
    if (value) {
        acl = posix_acl_from_xattr(value, size);
        if (IS_ERR(acl)) {
            return PTR_ERR(acl);
        }
        if (!acl) {
            return -EINVAL;
        }
        err = posix_acl_valid(acl);
        if (err) {
            return -EINVAL;
        }
        newacl = acl_alloc(ACLENT_T);
        newacl->acl_cnt=acl->a_count;
        sz=acl->a_count*newacl->acl_entry_size;
        newacl->acl_aclp=kmem_zalloc(sz, KM_SLEEP);
        printk("count:%i\n,sz=%lu,dim=%i,sizeof=%lu",acl->a_count,sz,newacl->acl_entry_size,sizeof(aclent_t));
        if(type==ACL_TYPE_DEFAULT) {
            flgs=ACL_DEFAULT;
        }
        ptr=newacl->acl_aclp;
        FOREACH_ACL_ENTRY(pa,acl,pe) {
            printk("entry: id %i, perm %i,ptr=%p\n",pa->e_id,pa->e_perm,ptr);
            if((uint64_t)ptr>= ((uint64_t)newacl->acl_aclp + (uint64_t)sz)) {
                printk("Damn!");
                return -ENOMEM; // Really it is -EID10TC0DER. Should _NEVER_ get there!
            }
            ptr->a_type=flgs|pa->e_tag; //Constants in Linux and Solaris for type field have different names but same numerical value. Not a clean way to deal with this, but for first tests it does its job quite well. TODO: Cleanup this.
            ptr->a_id=pa->e_id;
            ptr->a_perm=pa->e_perm;
            ptr++;
        }
// posix_acl_release(acl); // GPL-only !!!!!!!!!!
	
        printk("acl_type before:%i,cnt=%i\n",newacl->acl_type,newacl->acl_cnt);
        err=acl_translate(newacl,_ACL_ACE_ENABLED,S_ISDIR(ip->i_mode),ip->i_uid,ip->i_gid);
        printk("acl_type after:%i,cnt=%i\n",newacl->acl_type,newacl->acl_cnt);
        printk("translation:%i\n",err);
        sa.vsa_mask=VSA_ACE|VSA_ACECNT;
        sa.vsa_aclcnt=newacl->acl_cnt;
        sa.vsa_aclentp=newacl->acl_aclp;
        sa.vsa_aclentsz=newacl->acl_entry_size;
        sa.vsa_aclflags=0;
        cr = CRED();
        crhold(cr);
        err = zfs_setacl(ITOZ(ip), &sa, FALSE, cr);
        crfree(cr);
        acl_free(newacl);
        printk("setfacl retvalue=%i",err);
        if(err) {
            return -err;
        }

    }
    return 0;
}

ZPL_XATTR_GET_ACL_WRAPPER(zpl_xattr_acl_get);
ZPL_XATTR_SET_ACL_WRAPPER(zpl_xattr_acl_set);

xattr_handler_t zpl_xattr_acl_default_handler = {
    .prefix	= POSIX_ACL_XATTR_DEFAULT,
    .get	= zpl_xattr_acl_get,
    .set	= zpl_xattr_acl_set,
    .flags  = ACL_TYPE_DEFAULT
};
xattr_handler_t zpl_xattr_acl_access_handler = {
    .prefix	= POSIX_ACL_XATTR_ACCESS,
    .get	= zpl_xattr_acl_get,
    .set	= zpl_xattr_acl_set,
    .flags  = ACL_TYPE_ACCESS
};

