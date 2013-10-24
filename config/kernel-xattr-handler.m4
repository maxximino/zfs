dnl #
dnl # 2.6.35 API change,
dnl # The 'struct xattr_handler' was constified in the generic
dnl # super_block structure.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_CONST_XATTR_HANDLER],
	[AC_MSG_CHECKING([whether super_block uses const struct xattr_hander])
	ZFS_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
		#include <linux/xattr.h>

		const struct xattr_handler xattr_test_handler = {
			.prefix	= "test",
			.get	= NULL,
			.set	= NULL,
		};

		const struct xattr_handler *xattr_handlers[] = {
			&xattr_test_handler,
		};

		const struct super_block sb __attribute__ ((unused)) = {
			.s_xattr = xattr_handlers,
		};
	],[
	],[
		AC_MSG_RESULT([yes])
		AC_DEFINE(HAVE_CONST_XATTR_HANDLER, 1,
		          [super_block uses const struct xattr_hander])
	],[
		AC_MSG_RESULT([no])
	])
])

dnl #
dnl # 2.6.33 API change,
dnl # The xattr_hander->get() callback was changed to take a dentry
dnl # instead of an inode, and a handler_flags argument was added.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_XATTR_HANDLER_GET], [
	AC_MSG_CHECKING([whether xattr_handler->get() wants dentry])
	ZFS_LINUX_TRY_COMPILE([
		#include <linux/xattr.h>

		int get(struct dentry *dentry, const char *name,
		    void *buffer, size_t size, int handler_flags) { return 0; }
		static const struct xattr_handler
		    xops __attribute__ ((unused)) = {
			.get = get,
		};
	],[
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_DENTRY_XATTR_GET, 1,
		    [xattr_handler->get() wants dentry])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 2.6.33 API change,
dnl # The xattr_hander->set() callback was changed to take a dentry
dnl # instead of an inode, and a handler_flags argument was added.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_XATTR_HANDLER_SET], [
	AC_MSG_CHECKING([whether xattr_handler->set() wants dentry])
	ZFS_LINUX_TRY_COMPILE([
		#include <linux/xattr.h>

		int set(struct dentry *dentry, const char *name,
		    const void *buffer, size_t size, int flags,
		    int handler_flags) { return 0; }
		static const struct xattr_handler
		    xops __attribute__ ((unused)) = {
			.set = set,
		};
	],[
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_DENTRY_XATTR_SET, 1,
		    [xattr_handler->set() wants dentry])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 2.6.33 API change,
dnl # The xattr_hander->list() callback was changed to take a dentry
dnl # instead of an inode, and a handler_flags argument was added.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_XATTR_HANDLER_LIST], [
	AC_MSG_CHECKING([whether xattr_handler->list() wants dentry])
	ZFS_LINUX_TRY_COMPILE([
		#include <linux/xattr.h>

		size_t list(struct dentry *dentry, char *list, size_t list_size,
		    const char *name, size_t name_len, int handler_flags)
		    { return 0; }
		static const struct xattr_handler
		    xops __attribute__ ((unused)) = {
			.list = list,
		};
	],[
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_DENTRY_XATTR_LIST, 1,
		    [xattr_handler->list() wants dentry])
	],[
		AC_MSG_RESULT(no)
	])
])


dnl #
dnl # 3.7 API change,
dnl # The posix_acl_{from,to}_xattr functions gained a new
dnl # parameter: user_ns
dnl #
AC_DEFUN([ZFS_AC_KERNEL_POSIX_ACL_FROM_XATTR_USERNS], [
	AC_MSG_CHECKING([whether posix_acl_from_xattr() needs user_ns])
	ZFS_LINUX_TRY_COMPILE([
		#include <linux/cred.h>
		#include <linux/fs.h>
		#include <linux/posix_acl_xattr.h>
	],[
		posix_acl_from_xattr(&init_user_ns, NULL, 0);
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_POSIX_ACL_FROM_XATTR_USERNS, 1,
		    [posix_acl_from_xattr() needs user_ns])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 2.6.39 API change,
dnl # The is_owner_or_cap macro was replaced by
dnl # inode_owner_or_capable
dnl #
AC_DEFUN([ZFS_AC_KERNEL_INODE_OWNER_OR_CAPABLE], [
	AC_MSG_CHECKING([whether inode_owner_or_capable() exists])
	ZFS_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
	],[
		inode_owner_or_capable(NULL); 
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_INODE_OWNER_OR_CAPABLE, 1,
		    [inode_owner_or_capable() exists])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # Check if posix_acl_release can be used from a CDDL module,
dnl # The is_owner_or_cap macro was replaced by
dnl # inode_owner_or_capable
dnl #
AC_DEFUN([ZFS_AC_KERNEL_NONGPL_POSIX_ACL_RELEASE], [
	AC_MSG_CHECKING([whether posix_acl_release can be used from a CDDL module])
	ZFS_LINUX_TRY_COMPILE([
		#include <linux/cred.h>
		#include <linux/fs.h>
		#include <linux/posix_acl.h>
		MODULE_LICENSE("CDDL");
	],[
		struct posix_acl* tmp = posix_acl_alloc(1,0);
		posix_acl_release(tmp);
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_POSIX_ACL_RELEASE, 1,
		    [posix_acl_release can be used from a CDDL module])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 3.1 API change,
dnl # posix_acl_chmod_masq is not exported anymore
dnl # and posix_acl_chmod was introduced.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_POSIX_ACL_CHMOD], [
	AC_MSG_CHECKING([whether posix_acl_chmod exists])
	ZFS_LINUX_TRY_COMPILE([
                #include <linux/fs.h>
                #include <linux/posix_acl.h>
	],[
		posix_acl_chmod(NULL,0,0)
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_POSIX_ACL_CHMOD, 1,
		    [ posix_acl_chmod exists])
	],[
		AC_MSG_RESULT(no)
	])
])


dnl #
dnl # 2.6.32 API change,
dnl # Check if inode_operations contains the function check_acl
dnl #
AC_DEFUN([ZFS_AC_KERNEL_INODE_OPERATIONS_CHECK_ACL], [
	AC_MSG_CHECKING([whether struct inode_operations contains check_acl with 2 arguments])
	ZFS_LINUX_TRY_COMPILE([
                #include <linux/fs.h>

		int check_acl_fn(struct inode *inode, int mask)
		{ return 0;}

                static const struct inode_operations iops
                    __attribute__ ((unused)) = {
                        .check_acl = check_acl_fn,
                };
	
	],[
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_CHECK_ACL, 1,
		    [ struct inode_operations contains check_acl with 2 arguments])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 2.6.38 API change,
dnl # The function check_acl gained a new parameter: flags
dnl #
AC_DEFUN([ZFS_AC_KERNEL_INODE_OPERATIONS_CHECK_ACL_WITH_FLAGS], [
	AC_MSG_CHECKING([whether check_acl wants flags parameter])
	ZFS_LINUX_TRY_COMPILE([
                #include <linux/fs.h>

		int check_acl_fn(struct inode *inode, int mask,unsigned int flags)
		{ return 0;}

                static const struct inode_operations iops
                    __attribute__ ((unused)) = {
                        .check_acl = check_acl_fn,
                };
	
	],[
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_CHECK_ACL, 1,
		    [ struct inode_operations contains check_acl with 3 arguments])
		AC_DEFINE(HAVE_CHECK_ACL_WITH_FLAGS, 1,
		    [ check_acl wants flags parameter])
	],[
		AC_MSG_RESULT(no)
	])
])



dnl #
dnl # 3.1 API change,
dnl # Check if inode_operations contains the function get_acl
dnl #
AC_DEFUN([ZFS_AC_KERNEL_INODE_OPERATIONS_GET_ACL], [
	AC_MSG_CHECKING([whether struct inode_operations contains get_acl])
	ZFS_LINUX_TRY_COMPILE([
                #include <linux/fs.h>

		struct posix_acl * get_acl_fn(struct inode *inode,
						int type)
		{ return NULL;}

                static const struct inode_operations iops
                    __attribute__ ((unused)) = {
                        .get_acl = get_acl_fn,
                };
	
	],[
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_GET_ACL, 1,
		    [ struct inode_operations contains get_acl])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 2.6.30 API change,
dnl # caching of ACL into the inode was added in this version.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_POSIX_ACL_CACHING], [
	AC_MSG_CHECKING([whether struct inode has i_acl and i_default_acl])
	ZFS_LINUX_TRY_COMPILE([
                #include <linux/fs.h>

	],[
		struct inode ino;
		ino.i_acl = NULL;
		ino.i_default_acl = NULL;
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_POSIX_ACL_CACHING, 1,
		    [ struct inode contains i_acl and i_default_acl])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 2.6.30 API change,
dnl # current_umask exists only since this version.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_CURRENT_UMASK], [
	AC_MSG_CHECKING([whether current_umask exists])
	ZFS_LINUX_TRY_COMPILE([
                #include <linux/fs.h>

	],[
		current_umask();
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_CURRENT_UMASK, 1,
		    [ current_umask() exists])
	],[
		AC_MSG_RESULT(no)
	])
])



dnl #
dnl # 3.1 API change,
dnl # posix_acl_equiv_mode now wants an umode_t* instead of a mode_t*
dnl #
AC_DEFUN([ZFS_AC_KERNEL_POSIX_ACL_EQUIV_MODE_WANTS_UMODE_T], [
	AC_MSG_CHECKING([whether posix_acl_equiv_mode wants umode_t* ])
	ZFS_LINUX_TRY_COMPILE([
                #include <linux/fs.h>
                #include <linux/posix_acl.h>

	],[
		umode_t tmp;
		posix_acl_equiv_mode(NULL,&tmp);
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_POSIX_ACL_EQUIV_MODE_UMODE_T, 1,
		    [ posix_acl_equiv_mode wants umode_t*])
	],[
		AC_MSG_RESULT(no)
	])
])
