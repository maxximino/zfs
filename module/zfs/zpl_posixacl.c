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

static inline int acl_from_vsecattr(acl_t**newacl, vsecattr_t* sa) {
    acl_t* acl=NULL;
    acl=acl_alloc(ACE_T);
    if(acl==NULL) {
        return -ENOMEM;
    }
    acl->acl_cnt=	sa->vsa_aclcnt;
    acl->acl_aclp=	sa->vsa_aclentp;
    acl->acl_entry_size=	sa->vsa_aclentsz;
    *newacl=acl;
    return 0;
}
static int posixacl_from_ace(struct posix_acl** newacl,acl_t* acl,int posixacl_type) {
    struct posix_acl* pacl = NULL;
    struct posix_acl_entry* pae=NULL;
    aclent_t* ae;
    int idx=0,count=0;
    ae = acl->acl_aclp;
    //Count the elements we're interested in. (access OR default)
    if(posixacl_type==ACL_TYPE_DEFAULT) {
        for(idx=0; idx<acl->acl_cnt; idx++) {
            if(ae->a_type & ACL_DEFAULT) count++;
            ae++;
        }
    }
    else {
        for(idx=0; idx<acl->acl_cnt; idx++) {
            if(!(ae->a_type & ACL_DEFAULT)) count++;
            ae++;
        }
    }
    //Allocate the Posix ACL
    pacl=posix_acl_alloc(count,GFP_NOFS);
    if(pacl==NULL) {
        return -ENOMEM;
    }
    pae=pacl->a_entries;
    ae = acl->acl_aclp;
    //For each element in the acl_t
    for(idx=0; idx<acl->acl_cnt; idx++) {
        //if we are interested in this element
        if(posixacl_type==ACL_TYPE_DEFAULT) {
            if(!(ae->a_type & ACL_DEFAULT)) continue;
        }
        else {
            if(ae->a_type & ACL_DEFAULT) continue;
        }
        //copy informations from one structure to the other.
        pae->e_id = ae->a_id;
        pae->e_perm=    ae->a_perm ;
        pae->e_tag=(ae->a_type&(~ACL_DEFAULT)); //Constants in Linux and Solaris for type field have different names but same numerical value. Not a clean way to deal with this, but for first tests it does its job quite well. TODO: Cleanup this.
        pae++;
        ae++;
    }
    //copy the pointer to the new Posix ACL into the calling function.
    *newacl=pacl;
    return 0;
}


static int
__zpl_xattr_acl_get(struct inode *ip, const char *name,
                    void *value, size_t size,int type) {
    vsecattr_t sa;
    cred_t *cr;
    int err;
    acl_t * readacl;
    struct posix_acl* pacl = NULL;
    //Define what we're interested in
    sa.vsa_mask=VSA_ACE|VSA_ACECNT|VSA_ACE_ACLFLAGS|VSA_ACE_ALLTYPES;
    cr=CRED();
    crhold(cr);
    //Read the ACL (NFSv4-style into a vsecattr)
    err=zfs_getacl(ITOZ(ip),&sa,FALSE,cr);
    crfree(cr);
    if(err)
        return err;
    //Get an acl_t from vsecattr_t
    err=acl_from_vsecattr(&readacl,&sa);
    if(err)
        return err;
    //Translate the acl_t containing ace_t (NFSv4) into acl_t containing aclent_t (Posix ACL)
    err=acl_translate(readacl,_ACL_ACLENT_ENABLED,S_ISDIR(ip->i_mode),ip->i_uid,ip->i_gid);
    printk("translation:%i\n",err);
    if(err)
        return -err;
    //Get a Linux-style struct posix_acl from the acl_t containing aclent_t
    err=posixacl_from_ace(&pacl,readacl,type);
    if(err)
        return err;
    acl_free(readacl);
    err=posix_acl_to_xattr(pacl,value,size);
// posix_acl_release(pacl); // GPL-only !!!!!!!!!!
    return err;
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

