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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <sys/avl.h>
#if defined(_KERNEL)
#include <spl-debug.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include "acl_common.h"
#else
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <grp.h>
#include <pwd.h>
#include <acl_common.h>
#define	ASSERT	assert
#endif

#define	ACE_POSIX_SUPPORTED_BITS (ACE_READ_DATA | \
    ACE_WRITE_DATA | ACE_APPEND_DATA | ACE_EXECUTE | \
    ACE_READ_ATTRIBUTES | ACE_READ_ACL | ACE_WRITE_ACL)


#define	ACL_SYNCHRONIZE_SET_DENY		0x0000001
#define	ACL_SYNCHRONIZE_SET_ALLOW		0x0000002
#define	ACL_SYNCHRONIZE_ERR_DENY		0x0000004
#define	ACL_SYNCHRONIZE_ERR_ALLOW		0x0000008

#define	ACL_WRITE_OWNER_SET_DENY		0x0000010
#define	ACL_WRITE_OWNER_SET_ALLOW		0x0000020
#define	ACL_WRITE_OWNER_ERR_DENY		0x0000040
#define	ACL_WRITE_OWNER_ERR_ALLOW		0x0000080

#define	ACL_DELETE_SET_DENY			0x0000100
#define	ACL_DELETE_SET_ALLOW			0x0000200
#define	ACL_DELETE_ERR_DENY			0x0000400
#define	ACL_DELETE_ERR_ALLOW			0x0000800

#define	ACL_WRITE_ATTRS_OWNER_SET_DENY		0x0001000
#define	ACL_WRITE_ATTRS_OWNER_SET_ALLOW		0x0002000
#define	ACL_WRITE_ATTRS_OWNER_ERR_DENY		0x0004000
#define	ACL_WRITE_ATTRS_OWNER_ERR_ALLOW		0x0008000

#define	ACL_WRITE_ATTRS_WRITER_SET_DENY		0x0010000
#define	ACL_WRITE_ATTRS_WRITER_SET_ALLOW	0x0020000
#define	ACL_WRITE_ATTRS_WRITER_ERR_DENY		0x0040000
#define	ACL_WRITE_ATTRS_WRITER_ERR_ALLOW	0x0080000

#define	ACL_WRITE_NAMED_WRITER_SET_DENY		0x0100000
#define	ACL_WRITE_NAMED_WRITER_SET_ALLOW	0x0200000
#define	ACL_WRITE_NAMED_WRITER_ERR_DENY		0x0400000
#define	ACL_WRITE_NAMED_WRITER_ERR_ALLOW	0x0800000

#define	ACL_READ_NAMED_READER_SET_DENY		0x1000000
#define	ACL_READ_NAMED_READER_SET_ALLOW		0x2000000
#define	ACL_READ_NAMED_READER_ERR_DENY		0x4000000
#define	ACL_READ_NAMED_READER_ERR_ALLOW		0x8000000


#define	ACE_VALID_MASK_BITS (\
    ACE_READ_DATA | \
    ACE_LIST_DIRECTORY | \
    ACE_WRITE_DATA | \
    ACE_ADD_FILE | \
    ACE_APPEND_DATA | \
    ACE_ADD_SUBDIRECTORY | \
    ACE_READ_NAMED_ATTRS | \
    ACE_WRITE_NAMED_ATTRS | \
    ACE_EXECUTE | \
    ACE_DELETE_CHILD | \
    ACE_READ_ATTRIBUTES | \
    ACE_WRITE_ATTRIBUTES | \
    ACE_DELETE | \
    ACE_READ_ACL | \
    ACE_WRITE_ACL | \
    ACE_WRITE_OWNER | \
    ACE_SYNCHRONIZE)

#define	ACE_MASK_UNDEFINED			0x80000000

#define	ACE_VALID_FLAG_BITS (ACE_FILE_INHERIT_ACE | \
    ACE_DIRECTORY_INHERIT_ACE | \
    ACE_NO_PROPAGATE_INHERIT_ACE | ACE_INHERIT_ONLY_ACE | \
    ACE_SUCCESSFUL_ACCESS_ACE_FLAG | ACE_FAILED_ACCESS_ACE_FLAG | \
    ACE_IDENTIFIER_GROUP | ACE_OWNER | ACE_GROUP | ACE_EVERYONE)

#define START_TMPSIZE 100
#define DEFAULT_INHERIT_NEEDED_FLAGS ACE_INHERIT_ONLY_ACE
/*
* actually doesn't consider ACLs without ACE_INHERIT_ONLY_ACE as inheritable. PosixACL to NFSv4 writes default ACLS with this flag,
* so this is a problem only for externally written NFSv4 ACLs
*/
#define DEFAULT_INHERIT_ANYOF_FLAGS ( ACE_FILE_INHERIT_ACE | ACE_DIRECTORY_INHERIT_ACE | ACE_NO_PROPAGATE_INHERIT_ACE | ACE_INHERIT_ONLY_ACE )

#define READ_ENABLE_FLAGS ACE_READ_DATA
#define WRITE_ENABLE_FLAGS ACE_WRITE_DATA
#define EXEC_ENABLE_FLAGS ACE_EXECUTE

#define READ_DISABLE_FLAGS (ACE_READ_DATA | ACE_LIST_DIRECTORY | ACE_READ_NAMED_ATTRS | ACE_READ_ATTRIBUTES )
//#define WRITE_DISABLE_FLAGS ( ACE_WRITE_DATA | ACE_ADD_FILE | ACE_APPEND_DATA | ACE_ADD_SUBDIRECTORY | ACE_WRITE_NAMED_ATTRS | ACE_WRITE_ATTRIBUTES )
#define WRITE_DISABLE_FLAGS ( ACE_WRITE_DATA | ACE_ADD_FILE | ACE_APPEND_DATA | ACE_ADD_SUBDIRECTORY | ACE_WRITE_NAMED_ATTRS )
#define EXEC_DISABLE_FLAGS ACE_EXECUTE

#define compare_anyof(x,y) ((x & y) > 0)
#define compare_allof(x,y) ((x & y) == y)

typedef struct paclint {
aclent_t aclent;
int firstdeny;
int acceptedmask;
} paclint_t;

static int lookup_aclent(int posixtype,uid_t who, paclint_t** array, unsigned int*size,unsigned int*usedsize) {
    int i = 0;
    for(i = 0; i<(*size); i++) {
        if((*array)[i].aclent.a_type==0) {
            break;   //non inizializzato
        }
        if((*array)[i].aclent.a_type==posixtype) {
            if((posixtype==USER || posixtype==GROUP || posixtype==(ACL_DEFAULT|USER) ||posixtype==(ACL_DEFAULT|GROUP)) && ((*array)[i].aclent.a_id!=who) ) {
                continue;
            }
            else {
                return i; //trovato!!
            }
        }
    }
//creiamone uno nuovo.....
    if(i < *size) {
//ho posto....
        (*array)[i].aclent.a_type=posixtype;
        (*array)[i].aclent.a_id=who;
        (*usedsize)++;
        return i;
    }
    else {
//riallochiamo l'array :(
        printk("More than 100 elements in posix ACL not yet handled. Write the code!!! Continuing with WRONG results");
        return (*size)-1;
    }
}

static int get_posixtype(ace_t* cur_ace) {
    int posixtype=0;
    if(cur_ace->a_flags & ACE_OWNER) {
        posixtype=USER_OBJ;
    }
    else if(cur_ace->a_flags & ACE_GROUP) {
        posixtype=GROUP_OBJ;
    }
    else if(cur_ace->a_flags & ACE_EVERYONE) {
        posixtype=OTHER_OBJ;
    }
    else if(cur_ace->a_flags & ACE_IDENTIFIER_GROUP) {
        posixtype=GROUP;
    }
    else {
        posixtype=USER;
    }
    if(((cur_ace->a_flags & DEFAULT_INHERIT_NEEDED_FLAGS)==DEFAULT_INHERIT_NEEDED_FLAGS) && (cur_ace->a_flags & DEFAULT_INHERIT_ANYOF_FLAGS)) {
        posixtype |= ACL_DEFAULT;
    }
    printk("get_posixtype: %x diventa %x\n",cur_ace->a_flags,posixtype);
    return posixtype;
}
void copytype(int posixtype,paclint_t* from,unsigned int size,aclent_t* to,unsigned int*idx) {
    int i;
    for( i = 0; i<size; i++) {
        if(from[i].aclent.a_type==posixtype) {
            memcpy(&to[*idx],&(from[i].aclent),sizeof(aclent_t));
            (*idx)++;
        }
    }

}
int permissive_convert_ace_to_aent(ace_t *acebufp, int acecnt, boolean_t isdir,
                                   uid_t owner, gid_t group, aclent_t **retaclentp, int *retaclcnt) {
    unsigned int tmpsize = START_TMPSIZE;
    unsigned int usedsize=4,cpidx;
    int has_default = 0;
    int i=0,posixtype,removedperms,addedperms,idx;
    aclent_t* ret;
    paclint_t* tmp = (paclint_t*)kzalloc(sizeof(paclint_t)*tmpsize,GFP_NOFS); //ci conto che sia zero-filled!!
    ace_t* cur_ace;
    tmp[0].aclent.a_type=USER_OBJ;
    tmp[1].aclent.a_type=GROUP_OBJ;
    tmp[2].aclent.a_type=CLASS_OBJ;
    tmp[3].aclent.a_type=OTHER_OBJ;
    tmp[2].aclent.a_perm=7;
    printk("Permissive ACE to AENT: %i ACEs\n",acecnt);
    for(i =0; i<acecnt; i++) {
        cur_ace=&acebufp[i];
        if(cur_ace->a_type != ACE_ACCESS_ALLOWED_ACE_TYPE) {
            continue;
        }
        printk("ACE allow");
        posixtype = get_posixtype(cur_ace);
        printk("cerco %i\n",posixtype);
	if(posixtype & ACL_DEFAULT) has_default=1;
        idx = lookup_aclent(posixtype,cur_ace->a_who,&tmp,&tmpsize,&usedsize);
        addedperms=0;
        if(compare_allof(cur_ace->a_access_mask,READ_ENABLE_FLAGS)) {
            addedperms |= 4;
        }
        if(compare_allof(cur_ace->a_access_mask,WRITE_ENABLE_FLAGS)) {
            addedperms |=2 ;
        }
        if(compare_allof(cur_ace->a_access_mask,EXEC_ENABLE_FLAGS)) {
            addedperms |= 1;
        }
	
        printk(" Nidx=%i Pidx=%i addedperms=%x amask=%x who=%i posixtype=%x flags=%x\n",i,idx,addedperms,cur_ace->a_access_mask,cur_ace->a_who,posixtype,cur_ace->a_flags);
        tmp[idx].aclent.a_perm |=addedperms;
        tmp[idx].aclent.a_id=cur_ace->a_who;
    }
    for(i =0; i<acecnt; i++) {
        cur_ace=&acebufp[i];
        if(cur_ace->a_type != ACE_ACCESS_DENIED_ACE_TYPE) {
            continue;
        }
        printk("ACE deny");
        posixtype = get_posixtype(cur_ace);;
	if(posixtype & ACL_DEFAULT) has_default=1;
        idx = lookup_aclent(posixtype,cur_ace->a_who,&tmp,&tmpsize,&usedsize);
        removedperms=0;
        if(compare_anyof(cur_ace->a_access_mask,READ_DISABLE_FLAGS)) {
            removedperms |= 4;
        }
        if(compare_anyof(cur_ace->a_access_mask,WRITE_DISABLE_FLAGS)) {
            removedperms |=2 ;
        }
        if(compare_anyof(cur_ace->a_access_mask,EXEC_DISABLE_FLAGS)) {
            removedperms |= 1;
        }
        printk("Nidx=%i Pidx=%i removedperms=%x amask=%x who=%i posixtype=%x flags=%x\n",i,idx,removedperms,cur_ace->a_access_mask,cur_ace->a_who,posixtype,cur_ace->a_flags);
        tmp[idx].aclent.a_perm &= ~removedperms;
    }
    //MASCHERA NON ANCORA CONSIDERATA
    //HACK PER MASCHERA DEFAULT
    if(has_default){
    idx=lookup_aclent(ACL_DEFAULT|CLASS_OBJ,0,&tmp,&tmpsize,&usedsize);
    tmp[idx].aclent.a_perm=7;
    }
    printk("1'fase ok. %i elementi\n",usedsize);
    ret = (aclent_t*)kzalloc(sizeof(aclent_t)*usedsize,GFP_NOFS);
    cpidx = 0;
    copytype(USER_OBJ,tmp,usedsize,ret,&cpidx);
    copytype(USER,tmp,usedsize,ret,&cpidx);
    copytype(GROUP_OBJ,tmp,usedsize,ret,&cpidx);
    copytype(GROUP,tmp,usedsize,ret,&cpidx);
    copytype(CLASS_OBJ,tmp,usedsize,ret,&cpidx);
    copytype(OTHER_OBJ,tmp,usedsize,ret,&cpidx);
    copytype(ACL_DEFAULT|USER_OBJ,tmp,usedsize,ret,&cpidx);
    copytype(ACL_DEFAULT|USER,tmp,usedsize,ret,&cpidx);
    copytype(ACL_DEFAULT|GROUP_OBJ,tmp,usedsize,ret,&cpidx);
    copytype(ACL_DEFAULT|GROUP,tmp,usedsize,ret,&cpidx);
    copytype(ACL_DEFAULT|CLASS_OBJ,tmp,usedsize,ret,&cpidx);
    copytype(ACL_DEFAULT|OTHER_OBJ,tmp,usedsize,ret,&cpidx);
    *retaclentp = ret;
    *retaclcnt=usedsize;
    kfree(tmp);
    return 0;
}



