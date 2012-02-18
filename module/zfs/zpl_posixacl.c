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
#define ACE_POSIX_SUPPORTED_BITS (ACE_READ_DATA | \
		    ACE_WRITE_DATA | ACE_APPEND_DATA | ACE_EXECUTE | \
		    ACE_READ_ATTRIBUTES | ACE_READ_ACL | ACE_WRITE_ACL)

#define INVERTIBLE_BITS (ACE_POSIX_SUPPORTED_BITS)

/*
static void sanitize_nfsv4(acl_t* acl) {
    ace_t * oldptr=acl->acl_aclp;
    uint_t oldcount =acl->acl_cnt;
    ace_t* tmpptr=kmem_alloc(2*oldcount*acl->acl_entry_size,KM_SLEEP);
    ace_t* laptr; //look ahead ptr
    uint_t newcount=0;
    int idx;
    int create;
    printk("sanitize!\n");
    ASSERT(acl->acl_type==ACE_T);
    acl->acl_aclp=tmpptr;
    for(idx=0; idx<oldcount; idx++) {
	create=1;
    printk("iteration!\n");
	newcount++;
        memcpy(tmpptr,oldptr,acl->acl_entry_size);
	printk("addr=%p,ho=%i,flags=%i,type=%i,accmask=%i",tmpptr,tmpptr->a_who,tmpptr->a_flags,tmpptr->a_type,tmpptr->a_access_mask);
//clear every non-posix-supported bits
        tmpptr->a_access_mask = tmpptr->a_access_mask & ACE_POSIX_SUPPORTED_BITS;
//	if((tmpptr->a_access_mask & ACE_WRITE_DATA) || (tmpptr->a_flags & ACE_OWNER)){
	if(tmpptr->a_flags & ACE_OWNER){
	//tmpptr->a_access_mask |= ACE_WRITE_ATTRIBUTES;
	}
        if(tmpptr->a_type==ACE_ACCESS_ALLOWED_ACE_TYPE) {
	   printk("is an allow ace\n");
            if(idx <(oldcount-1)) {
		    printk("a following entry exists.\n");
                laptr=(oldptr+1);
                printk("oldptr=%p,laptr=%p\n",oldptr,laptr);
		if((laptr->a_who == tmpptr->a_who) && (laptr->a_flags == tmpptr->a_flags) && (laptr->a_type & ACE_ACCESS_DENIED_ACE_TYPE)) {
			printk("the following entry is OK.\n");
                    create=0;
                }
            }
	    //no, does not exists. Create the deny entry.
	    if(create==1){newcount++;
	    tmpptr++;
            memcpy(tmpptr,(tmpptr-1),acl->acl_entry_size);
	    tmpptr->a_type=ACE_ACCESS_DENIED_ACE_TYPE;
	    tmpptr->a_access_mask= tmpptr->a_access_mask ^ INVERTIBLE_BITS;
	    printk("Created correspoding deny entry.\n");
	printk("addr=%p,ho=%i,flags=%i,type=%i,accmask=%i",tmpptr,tmpptr->a_who,tmpptr->a_flags,tmpptr->a_type,tmpptr->a_access_mask);
	    }
        }
	tmpptr++;
	oldptr++;
    }
    //must free the old memory!! leaking!
    acl->acl_cnt=newcount;
}
*/
static inline int acl_from_vsecattr(acl_t**newacl, vsecattr_t* sa) {
    acl_t* acl=NULL;
    acl=acl_alloc(ACE_T);
    if(unlikely(acl==NULL)) {
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
    //Count the elements we're interested in. access OR default)
    if(posixacl_type==ACL_TYPE_DEFAULT) {
        for(idx=0; idx<acl->acl_cnt; idx++) {
            if((ae->a_type & ACL_DEFAULT)==ACL_DEFAULT) count++;
            ae++;
        }
    }
    else {
        for(idx=0; idx<acl->acl_cnt; idx++) {
            if((ae->a_type & ACL_DEFAULT)==0) { printk("\n%x - id %i - perm %i CONTATO PER ACCESS ",ae->a_type,ae->a_id,ae->a_perm); count++; }
            ae++;
        }
    }
    //Allocate the Posix ACL
    printk(" alloco %i mentre prima erano %i \n",count,acl->acl_cnt);
    pacl=posix_acl_alloc(count,GFP_NOFS);
    if(unlikely(pacl==NULL)) {
        return -ENOMEM;
    }
    pae=pacl->a_entries;
    ae = acl->acl_aclp;
    //For each element in the acl_t
    for(idx=0; idx<acl->acl_cnt; idx++) {
        //if we are interested in this element
        if(posixacl_type==ACL_TYPE_DEFAULT) {
            if(!(ae->a_type & ACL_DEFAULT)) { ae++; continue;}
        }
        else {
            if(ae->a_type & ACL_DEFAULT) {ae++;continue;}
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

static int get_aclents_from_inode(acl_t ** newacl, struct inode* ip) {
    vsecattr_t sa;
    int err;
    acl_t * readacl;
    cred_t *cr;
    //Define what we're interested in
    sa.vsa_mask=VSA_ACE|VSA_ACECNT|VSA_ACE_ACLFLAGS|VSA_ACE_ALLTYPES;
    cr=CRED();
    crhold(cr);
    //Read the ACL (NFSv4-style into a vsecattr)
    err=zfs_getacl(ITOZ(ip),&sa,FALSE,cr);
    crfree(cr);
    if(unlikely(err)) { //free mem into pointers in vsecattr
        return err;
    }
    //Get an acl_t from vsecattr_t
    err=acl_from_vsecattr(&readacl,&sa);
    if(unlikely(err)) { //idem
        return err;
    }
    printk("NFSv4 ACL on disk: acl_cnt:%i\n",readacl->acl_cnt);
    //Translate the acl_t containing ace_t (NFSv4) into acl_t containing aclent_t (Posix ACL)
    //sanitize_nfsv4(readacl); //Temporary disabling this.
    printk("NFSv4 ACL after sanitize: acl_cnt:%i\n",readacl->acl_cnt);
    err=acl_translate(readacl,_ACL_ACLENT_ENABLED,S_ISDIR(ip->i_mode),ip->i_uid,ip->i_gid);
    printk("Translation of ACL from disk:%i\n",err);
    if(unlikely(err)) { // + free acl_t
        return -err;
    }
    //copy the pointer into the calling function.
    *newacl=readacl;
    return 0;
}
static int
__zpl_xattr_acl_get(struct inode *ip, const char *name,
                    void *value, size_t size,int type) {
    int err;
    acl_t * readacl;
    struct posix_acl* pacl = NULL;
    err=get_aclents_from_inode(&readacl,ip);
    if(unlikely(err)) {
        return err;
    }
    //Get a Linux-style struct posix_acl from the acl_t containing aclent_t
    err=posixacl_from_ace(&pacl,readacl,type);
    if(unlikely(err)) {
        acl_free(readacl);
        return err;
    }
    acl_free(readacl);
    err=posix_acl_to_xattr(pacl,value,size);
// posix_acl_release(pacl); // GPL-only !!!!!!!!!!
    return err;
}

static int aclent_from_posixacl(acl_t ** newacl,struct posix_acl* pacl,int type) {
    struct posix_acl_entry *pa,*pe;
    acl_t* acl=NULL;
    aclent_t* ptr;
    unsigned long sz=0;
    int flgs=0;
    acl = acl_alloc(ACLENT_T);
    if(unlikely(!acl)) {
        return -ENOMEM;
    }
    acl->acl_cnt=pacl->a_count;
    //Calculate and allocate memory for the ace_t array.
    sz=(pacl->a_count) * (acl->acl_entry_size);
    acl->acl_aclp=kmem_zalloc(sz, KM_SLEEP);
    if(unlikely(!acl->acl_aclp)) {
        return -ENOMEM;
    }
    //Add the ACL_DEFAULT flag only if necessary.
    if(type==ACL_TYPE_DEFAULT) {
        flgs=ACL_DEFAULT;
    }
    ptr=acl->acl_aclp;
    //Copy each entry between structures.
    FOREACH_ACL_ENTRY(pa,pacl,pe) {
        ptr->a_type=flgs|pa->e_tag; //Constants in Linux and Solaris for type field have different names but same numerical value. Not a clean way to deal with this, but for first tests it does its job quite well. TODO: Cleanup this.
        ptr->a_id=pa->e_id;
        ptr->a_perm=pa->e_perm;
        printk("from linux posix to solaris posixacl: type %x id %i perm %i\n",pa->e_tag,pa->e_id,pa->e_perm);
	ptr++;
    }
    //Set the destination variable to the right pointer.
    *newacl=acl;
    return 0;
}

static int write_nfsv4_acl(struct inode *ip,acl_t* newacl) {
    vsecattr_t sa;
    cred_t *cr;
    int err=0;
    //Populate the vsecattr_t structure
    sa.vsa_mask=VSA_ACE|VSA_ACECNT;
    sa.vsa_aclcnt=newacl->acl_cnt;
    sa.vsa_aclentp=newacl->acl_aclp;
    sa.vsa_aclentsz=newacl->acl_entry_size;
    sa.vsa_aclflags=0;
    cr = CRED();
    crhold(cr);
    err = zfs_setacl(ITOZ(ip), &sa, FALSE, cr);
    crfree(cr);
    return err;
}
static int merge_acls(acl_t ** dest, acl_t* objacl, acl_t *defacl) {
    acl_t* tmp;
    aclent_t* ae;
    aclent_t* dst_ae;
    int count=0,idx=0,sz=0;
    ASSERT(objacl->acl_type==ACLENT_T);
    ASSERT(defacl->acl_type==ACLENT_T);
    tmp=acl_alloc(ACLENT_T);
    if(unlikely(!tmp)) {
        return -ENOMEM;
    }
    printk("MERGING TWO ACLs\n");
    ae = objacl->acl_aclp;
    //Count elements to be allocated for destination ACL
    for(idx=0; idx<objacl->acl_cnt; idx++) {
        if(!(ae->a_type & ACL_DEFAULT)) count++;
        ae++;
    }
    ae = defacl->acl_aclp;
    for(idx=0; idx<defacl->acl_cnt; idx++) {
        if(ae->a_type & ACL_DEFAULT) count++;
        ae++;
    }
    tmp->acl_cnt=count;
    //Allocate array of acl entries
    sz=count * (tmp->acl_entry_size);
    tmp->acl_aclp=kmem_zalloc(sz, KM_SLEEP);
    printk("Found %i elements to be copied. %i bytes each. %i bytes tot.sizeof %lu\n",count,tmp->acl_entry_size,sz,sizeof(aclent_t));
    if(unlikely(!tmp->acl_aclp)) {
        return -ENOMEM;
    }
    ae = objacl->acl_aclp;
    dst_ae=tmp->acl_aclp;
    //Copy elements
    for(idx=0; idx<objacl->acl_cnt; idx++) {
        printk("Element in objacl. type=%i, id=%i, perm=%i ae=%p dst_ae=%p\n",ae->a_type,ae->a_id,ae->a_perm,ae,dst_ae);
        if(!(ae->a_type & ACL_DEFAULT)) {
            memcpy(dst_ae,ae,objacl->acl_entry_size);
            dst_ae++;
            printk("copied.\n");
        }
        ae++;
    }
    ae = defacl->acl_aclp;
    for(idx=0; idx<defacl->acl_cnt; idx++) {
        printk("Element in defacl. type=%i, id=%i, perm=%i\n",ae->a_type,ae->a_id,ae->a_perm);
        if(ae->a_type & ACL_DEFAULT) {
            memcpy(dst_ae,ae,defacl->acl_entry_size);
            dst_ae++;
            printk("copied.\n");
        }
        ae++;
    }
    //if the *dest->acl_type is ACLENT_T, *dest is a valid ACL. It will be overwritten, so free it instead of leaking memory!
    if(likely((*dest)->acl_type == ACLENT_T)) {
        acl_free(*dest);
    }
    *dest=tmp;
    return 0;
}
static int
__zpl_xattr_acl_set(struct inode *ip, const char *name,
                    const void *value, size_t size, int flags,int type) {
    struct posix_acl * acl = NULL;
    acl_t* newacl=NULL;
    acl_t* oldacl=NULL;
    int err = 0;
    printk("Starting acl_set\n");
    if(unlikely((type != ACL_TYPE_DEFAULT) && (type != ACL_TYPE_ACCESS))) {
        return -EINVAL;
    }
    if(unlikely(!inode_owner_or_capable(ip))) {
        return -EPERM;
    }
    if(unlikely(!value)) {
        return -EINVAL;
    }
    acl = posix_acl_from_xattr(value, size);
    if(unlikely(IS_ERR(acl))) {
        return PTR_ERR(acl);
    }
    if(unlikely(!acl)) {
        return -EINVAL;
    }
    err = posix_acl_valid(acl);
    if(unlikely(err)) {
        //Free acl. see posix_acl_release problem.
        return -EINVAL;
    }
    err=aclent_from_posixacl(&newacl,acl,type);
    if(unlikely(err)) {
        //Free acl. see posix_acl_release problem.
        return err;
    }
// posix_acl_release(acl); // GPL-only !!!!!!!!!!
    //if it is a directory, it has an ACCESS and a DEFAULT acl. In the posix ACL we have only one of them,but in the acl_t we should put them both.
    //So get the missing part!
    if(S_ISDIR(ip->i_mode)) {
        err=get_aclents_from_inode(&oldacl,ip);
        if(unlikely(err)) {
            acl_free(newacl);
            return err;
        }
        if(type==ACL_TYPE_DEFAULT) {
            //if this is a default acl, take the default entries from the new and the access entries from the old.
            //and put them in the newacl.
            err=merge_acls(&newacl,oldacl,newacl);
            if(unlikely(err)) {
                acl_free(newacl);
                acl_free(oldacl);
                return err;
            }
        }
        else if(type==ACL_TYPE_ACCESS){
            // this is an access acl, take the access entries from the new and the default entries from the old.
            err=merge_acls(&newacl,newacl,oldacl);
            if(unlikely(err)) {
                acl_free(newacl);
                acl_free(oldacl);
                return err;
            }
        }
else{
printk("What the fuck?"); return -1;
}
        acl_free(oldacl);
    }
    err=acl_translate(newacl,_ACL_ACE_ENABLED,S_ISDIR(ip->i_mode),ip->i_uid,ip->i_gid);
    if(unlikely(err)) {
        printk("Translation of new acl failed.%i\n",err);
        acl_free(newacl);
        return err;
    }
    printk("Translation of new acl succeeded.\n");
    err=write_nfsv4_acl(ip,newacl);
    acl_free(newacl);
    if(unlikely(err)) {
        return -err;
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

