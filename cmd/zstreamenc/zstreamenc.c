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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2012 Martin Matuska <martin@matuska.org>
 */

#include <libnvpair.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include <sys/dmu.h>
#include <sys/zfs_ioctl.h>
#include <zfs_fletcher.h>

uint64_t drr_record_count[DRR_NUMTYPES];
uint64_t total_write_size = 0;
uint64_t total_stream_len = 0;
FILE *send_stream = 0;
boolean_t do_byteswap = B_FALSE;
#define	INITIAL_BUFLEN (1<<20)

static void
usage(void)
{
	(void) fprintf(stderr, "usage: zstreamenc [-v] < file >encstream\n");
	(void) fprintf(stderr, "\t -v -- verbose\n");
	exit(1);
}

/*
 * ssread - send stream read.
 *
 * Read while computing incremental checksum
 */

static size_t
ssread(void *buf, size_t len, zio_cksum_t *cksum)
{
	size_t outlen;

	if ((outlen = fread(buf, len, 1, send_stream)) == 0)
		return (0);

	if (cksum) {
		if (do_byteswap)
			fletcher_4_incremental_byteswap(buf, len, cksum);
		else
			fletcher_4_incremental_native(buf, len, cksum);
	}
	total_stream_len += len;
	return (outlen);
}

static size_t encbuf(void* buf,size_t len,zio_cksum_t* cksum,zio_cksum_t* newcksum,int encrypt,int output){
        size_t ret = ssread(buf,len,cksum);
	if(encrypt){
		char* cbuf = (char*)buf;
		size_t n;
		 for( n = 0; n < len; n++){
			cbuf[n] = cbuf[n]^0b10101010; //fake encryption, replace with something more serious.
		 }
	}
	if (output && newcksum) {
		if (do_byteswap)
			fletcher_4_incremental_byteswap(buf, len, newcksum);
		else
			fletcher_4_incremental_native(buf, len, newcksum);
	}    
	if(output){fwrite(buf,len,1,stdout);}
	return ret;
}
#define print_record() if (do_byteswap)	fletcher_4_incremental_byteswap(drr,  sizeof(dmu_replay_record_t), &new_zc); else fletcher_4_incremental_native(drr, sizeof(dmu_replay_record_t), &new_zc); fwrite(drr,sizeof(dmu_replay_record_t),1,stdout)


int
main(int argc, char *argv[])
{
	char *buf = malloc(INITIAL_BUFLEN);
	dmu_replay_record_t thedrr;
	dmu_replay_record_t *drr = &thedrr;
	struct drr_begin *drrb = &thedrr.drr_u.drr_begin;
	struct drr_end *drre = &thedrr.drr_u.drr_end;
	struct drr_object *drro = &thedrr.drr_u.drr_object;
	struct drr_freeobjects *drrfo = &thedrr.drr_u.drr_freeobjects;
	struct drr_write *drrw = &thedrr.drr_u.drr_write;
	struct drr_write_byref *drrwbr = &thedrr.drr_u.drr_write_byref;
	struct drr_free *drrf = &thedrr.drr_u.drr_free;
	struct drr_spill *drrs = &thedrr.drr_u.drr_spill;
	char c;
	boolean_t verbose = B_FALSE;
	boolean_t first = B_TRUE;
	boolean_t set_other = B_FALSE;
	int err;
	zio_cksum_t zc = { { 0 } };
	zio_cksum_t new_zc = { { 0 } };
	zio_cksum_t pcksum = { { 0 } };
	zio_cksum_t new_pcksum = { { 0 } };

	while ((c = getopt(argc, argv, ":vo")) != -1) {
		switch (c) {
		case 'o':
			set_other = B_TRUE;
		case 'v':
			verbose = B_TRUE;
			break;
		case ':':
			(void) fprintf(stderr,
			    "missing argument for '%c' option\n", optopt);
			usage();
			break;
		case '?':
			(void) fprintf(stderr, "invalid option '%c'\n",
			    optopt);
			usage();
		}
	}

	if (isatty(STDIN_FILENO)) {
		(void) fprintf(stderr,
		    "Error: Backup stream can not be read "
		    "from a terminal.\n"
		    "You must redirect standard input.\n");
		exit(1);
	}

	send_stream = stdin;
	pcksum = zc;
	new_pcksum = new_zc;
	while (encbuf(drr, sizeof (dmu_replay_record_t), &zc,&new_zc,0,0)) {

		if (first) {
			if (drrb->drr_magic == BSWAP_64(DMU_BACKUP_MAGIC)) {
				do_byteswap = B_TRUE;
					ZIO_SET_CHECKSUM(&zc, 0, 0, 0, 0);
					ZIO_SET_CHECKSUM(&new_zc, 0, 0, 0, 0);
					/*
					 * recalculate header checksum now
					 * that we know it needs to be
					 * byteswapped.
					 */
					fletcher_4_incremental_byteswap(drr,
					    sizeof (dmu_replay_record_t), &new_zc);

					 fletcher_4_incremental_byteswap(drr,
					    sizeof (dmu_replay_record_t), &zc);
			} else if (drrb->drr_magic != DMU_BACKUP_MAGIC) {
				(void) fprintf(stderr, "Invalid stream "
				    "(bad magic number)\n");
				exit(1);
			}
			first = B_FALSE;
		}
		if (do_byteswap) {
			drr->drr_type = BSWAP_32(drr->drr_type);
			drr->drr_payloadlen =
			    BSWAP_32(drr->drr_payloadlen);
		}

		/*
		 * At this point, the leading fields of the replay record
		 * (drr_type and drr_payloadlen) have been byte-swapped if
		 * necessary, but the rest of the data structure (the
		 * union of type-specific structures) is still in its
		 * original state.
		 */
		if (drr->drr_type >= DRR_NUMTYPES) {
			(void) fprintf(stderr,"INVALID record found: type 0x%x\n",
			    drr->drr_type);
			(void) fprintf(stderr,"Aborting.\n");
			exit(1);
		}

		drr_record_count[drr->drr_type]++;

		switch (drr->drr_type) {
		case DRR_BEGIN:
			if (do_byteswap) {
				drrb->drr_magic = BSWAP_64(drrb->drr_magic);
				drrb->drr_versioninfo =
				    BSWAP_64(drrb->drr_versioninfo);
				drrb->drr_creation_time =
				    BSWAP_64(drrb->drr_creation_time);
				drrb->drr_type = BSWAP_32(drrb->drr_type);
				drrb->drr_flags = BSWAP_32(drrb->drr_flags);
				drrb->drr_toguid = BSWAP_64(drrb->drr_toguid);
				drrb->drr_fromguid =
				    BSWAP_64(drrb->drr_fromguid);
			}

			(void) fprintf(stderr,"BEGIN record\n");
			(void) fprintf(stderr,"\thdrtype = %lld\n",
			    DMU_GET_STREAM_HDRTYPE(drrb->drr_versioninfo));
			(void) fprintf(stderr,"\tfeatures = %llx\n",
			    DMU_GET_FEATUREFLAGS(drrb->drr_versioninfo));
			(void) fprintf(stderr,"\tmagic = %llx\n",
			    (u_longlong_t)drrb->drr_magic);
			(void) fprintf(stderr,"\tcreation_time = %llx\n",
			    (u_longlong_t)drrb->drr_creation_time);
			(void) fprintf(stderr,"\ttype = %u\n", drrb->drr_type);
			(void) fprintf(stderr,"\tflags = 0x%x\n", drrb->drr_flags);
			(void) fprintf(stderr,"\ttoguid = %llx\n",
			    (u_longlong_t)drrb->drr_toguid);
			(void) fprintf(stderr,"\tfromguid = %llx\n",
			    (u_longlong_t)drrb->drr_fromguid);
			(void) fprintf(stderr,"\ttoname = %s\n", drrb->drr_toname);
			if (verbose)(void) fprintf(stderr,"\n");


			drrb->drr_type = set_other? DMU_OST_OTHER : DMU_OST_ZFS;
if (do_byteswap) {
				drrb->drr_magic = BSWAP_64(drrb->drr_magic);
				drrb->drr_versioninfo =
				    BSWAP_64(drrb->drr_versioninfo);
				drrb->drr_creation_time =
				    BSWAP_64(drrb->drr_creation_time);
				drrb->drr_type = BSWAP_32(drrb->drr_type);
				drrb->drr_flags = BSWAP_32(drrb->drr_flags);
				drrb->drr_toguid = BSWAP_64(drrb->drr_toguid);
				drrb->drr_fromguid =
				    BSWAP_64(drrb->drr_fromguid);
			}
			print_record();
	if (do_byteswap) {
				drrb->drr_magic = BSWAP_64(drrb->drr_magic);
				drrb->drr_versioninfo =
				    BSWAP_64(drrb->drr_versioninfo);
				drrb->drr_creation_time =
				    BSWAP_64(drrb->drr_creation_time);
				drrb->drr_type = BSWAP_32(drrb->drr_type);
				drrb->drr_flags = BSWAP_32(drrb->drr_flags);
				drrb->drr_toguid = BSWAP_64(drrb->drr_toguid);
				drrb->drr_fromguid =
				    BSWAP_64(drrb->drr_fromguid);
			}		if ((DMU_GET_STREAM_HDRTYPE(drrb->drr_versioninfo) ==
			    DMU_COMPOUNDSTREAM) && drr->drr_payloadlen != 0) {
				nvlist_t *nv;
				int sz = drr->drr_payloadlen;

				if (sz > 1<<20) {
					free(buf);
					buf = malloc(sz);
				}
				(void) encbuf(buf, sz, &zc,&new_zc,0,1);
				if (ferror(send_stream))
					perror("fread");
				err = nvlist_unpack(buf, sz, &nv, 0);
				if (err)
					perror(strerror(err));
				nvlist_print(stdout, nv);
				nvlist_free(nv);
			}
			break;

		case DRR_END:
			if (do_byteswap) {
				drre->drr_checksum.zc_word[0] =
				    BSWAP_64(drre->drr_checksum.zc_word[0]);
				drre->drr_checksum.zc_word[1] =
				    BSWAP_64(drre->drr_checksum.zc_word[1]);
				drre->drr_checksum.zc_word[2] =
				    BSWAP_64(drre->drr_checksum.zc_word[2]);
				drre->drr_checksum.zc_word[3] =
				    BSWAP_64(drre->drr_checksum.zc_word[3]);
			}
			/*
			 * We compare against the *previous* checksum
			 * value, because the stored checksum is of
			 * everything before the DRR_END record.
			 */
			if (!ZIO_CHECKSUM_EQUAL(drre->drr_checksum,
			    pcksum)) {
				(void) fprintf(stderr,"Expected checksum differs from "
				    "checksum in stream.\n");
				(void) fprintf(stderr,"Expected checksum = "
				    "%llx/%llx/%llx/%llx\n",
				    (long long unsigned int)pcksum.zc_word[0],
				    (long long unsigned int)pcksum.zc_word[1],
				    (long long unsigned int)pcksum.zc_word[2],
				    (long long unsigned int)pcksum.zc_word[3]);
			}
				(void) fprintf(stderr,"Expected NEW checksum = "
				    "%llx/%llx/%llx/%llx\n",
				    (long long unsigned int)new_pcksum.zc_word[0],
				    (long long unsigned int)new_pcksum.zc_word[1],
				    (long long unsigned int)new_pcksum.zc_word[2],
				    (long long unsigned int)new_pcksum.zc_word[3]);

			(void) fprintf(stderr,"END checksum = %llx/%llx/%llx/%llx\n",
			    (long long unsigned int)
			    drre->drr_checksum.zc_word[0],
			    (long long unsigned int)
			    drre->drr_checksum.zc_word[1],
			    (long long unsigned int)
			    drre->drr_checksum.zc_word[2],
			    (long long unsigned int)
			    drre->drr_checksum.zc_word[3]);
				
				drre->drr_checksum.zc_word[0] =new_pcksum.zc_word[0];
				drre->drr_checksum.zc_word[1] =new_pcksum.zc_word[1];
				drre->drr_checksum.zc_word[2] =new_pcksum.zc_word[2];
				drre->drr_checksum.zc_word[3] =new_pcksum.zc_word[3];
			if (do_byteswap) {
				drre->drr_checksum.zc_word[0] =
				    BSWAP_64(drre->drr_checksum.zc_word[0]);
				drre->drr_checksum.zc_word[1] =
				    BSWAP_64(drre->drr_checksum.zc_word[1]);
				drre->drr_checksum.zc_word[2] =
				    BSWAP_64(drre->drr_checksum.zc_word[2]);
				drre->drr_checksum.zc_word[3] =
				    BSWAP_64(drre->drr_checksum.zc_word[3]);
			}
	print_record();
			ZIO_SET_CHECKSUM(&zc, 0, 0, 0, 0);
			ZIO_SET_CHECKSUM(&new_zc, 0, 0, 0, 0);
			break;

		case DRR_OBJECT:
			print_record();
			if (do_byteswap) {
				drro->drr_object = BSWAP_64(drro->drr_object);
				drro->drr_type = BSWAP_32(drro->drr_type);
				drro->drr_bonustype =
				    BSWAP_32(drro->drr_bonustype);
				drro->drr_blksz = BSWAP_32(drro->drr_blksz);
				drro->drr_bonuslen =
				    BSWAP_32(drro->drr_bonuslen);
				drro->drr_toguid = BSWAP_64(drro->drr_toguid);
			}
			if (verbose) {
				(void) fprintf(stderr,"OBJECT object = %llu type = %u "
				    "bonustype = %u blksz = %u bonuslen = %u\n",
				    (u_longlong_t)drro->drr_object,
				    drro->drr_type,
				    drro->drr_bonustype,
				    drro->drr_blksz,
				    drro->drr_bonuslen);
			}
			if (drro->drr_bonuslen > 0) {
				(void) encbuf(buf, P2ROUNDUP(drro->drr_bonuslen,
				    8), &zc,&new_zc,1,1);
			}
			break;

		case DRR_FREEOBJECTS:
			print_record();
			if (do_byteswap) {
				drrfo->drr_firstobj =
				    BSWAP_64(drrfo->drr_firstobj);
				drrfo->drr_numobjs =
				    BSWAP_64(drrfo->drr_numobjs);
				drrfo->drr_toguid = BSWAP_64(drrfo->drr_toguid);
			}
			if (verbose) {
				(void) fprintf(stderr,"FREEOBJECTS firstobj = %llu "
				    "numobjs = %llu\n",
				    (u_longlong_t)drrfo->drr_firstobj,
				    (u_longlong_t)drrfo->drr_numobjs);
			}
			break;

		case DRR_WRITE:
			print_record();
			if (do_byteswap) {
				drrw->drr_object = BSWAP_64(drrw->drr_object);
				drrw->drr_type = BSWAP_32(drrw->drr_type);
				drrw->drr_offset = BSWAP_64(drrw->drr_offset);
				drrw->drr_length = BSWAP_64(drrw->drr_length);
				drrw->drr_toguid = BSWAP_64(drrw->drr_toguid);
				drrw->drr_key.ddk_prop =
				    BSWAP_64(drrw->drr_key.ddk_prop);
			}
			if (verbose) {
				(void) fprintf(stderr,"WRITE object = %llu type = %u "
				    "checksum type = %u\n"
				    "offset = %llu length = %llu "
				    "props = %llx\n",
				    (u_longlong_t)drrw->drr_object,
				    drrw->drr_type,
				    drrw->drr_checksumtype,
				    (u_longlong_t)drrw->drr_offset,
				    (u_longlong_t)drrw->drr_length,
				    (u_longlong_t)drrw->drr_key.ddk_prop);
			}
			(void) encbuf(buf, drrw->drr_length, &zc,&new_zc,1,1);
			total_write_size += drrw->drr_length;
			break;

		case DRR_WRITE_BYREF:
			print_record();
			if (do_byteswap) {
				drrwbr->drr_object =
				    BSWAP_64(drrwbr->drr_object);
				drrwbr->drr_offset =
				    BSWAP_64(drrwbr->drr_offset);
				drrwbr->drr_length =
				    BSWAP_64(drrwbr->drr_length);
				drrwbr->drr_toguid =
				    BSWAP_64(drrwbr->drr_toguid);
				drrwbr->drr_refguid =
				    BSWAP_64(drrwbr->drr_refguid);
				drrwbr->drr_refobject =
				    BSWAP_64(drrwbr->drr_refobject);
				drrwbr->drr_refoffset =
				    BSWAP_64(drrwbr->drr_refoffset);
				drrwbr->drr_key.ddk_prop =
				    BSWAP_64(drrwbr->drr_key.ddk_prop);
			}
			if (verbose) {
				(void) fprintf(stderr,"WRITE_BYREF object = %llu "
				    "checksum type = %u props = %llx\n"
				    "offset = %llu length = %llu\n"
				    "toguid = %llx refguid = %llx\n"
				    "refobject = %llu refoffset = %llu\n",
				    (u_longlong_t)drrwbr->drr_object,
				    drrwbr->drr_checksumtype,
				    (u_longlong_t)drrwbr->drr_key.ddk_prop,
				    (u_longlong_t)drrwbr->drr_offset,
				    (u_longlong_t)drrwbr->drr_length,
				    (u_longlong_t)drrwbr->drr_toguid,
				    (u_longlong_t)drrwbr->drr_refguid,
				    (u_longlong_t)drrwbr->drr_refobject,
				    (u_longlong_t)drrwbr->drr_refoffset);
			}
			break;

		case DRR_FREE:
			print_record();
			if (do_byteswap) {
				drrf->drr_object = BSWAP_64(drrf->drr_object);
				drrf->drr_offset = BSWAP_64(drrf->drr_offset);
				drrf->drr_length = BSWAP_64(drrf->drr_length);
			}
			if (verbose) {
				(void) fprintf(stderr,"FREE object = %llu "
				    "offset = %llu length = %lld\n",
				    (u_longlong_t)drrf->drr_object,
				    (u_longlong_t)drrf->drr_offset,
				    (longlong_t)drrf->drr_length);
			}
			break;
		case DRR_SPILL:
			print_record();
			if (do_byteswap) {
				drrs->drr_object = BSWAP_64(drrs->drr_object);
				drrs->drr_length = BSWAP_64(drrs->drr_length);
			}
			if (verbose) {
				(void) fprintf(stderr,"SPILL block for object = %llu "
				    "length = %llu\n",
				    (long long unsigned int)drrs->drr_object,
				    (long long unsigned int)drrs->drr_length);
			}
			(void) encbuf(buf, drrs->drr_length, &zc,&new_zc,1,1);
			break;
		case DRR_NUMTYPES:
			/* should never be reached */
			exit(1);
		}
		pcksum = zc;
		new_pcksum = new_zc;
	}
	free(buf);

	/* Print final summary */

	(void) fprintf(stderr,"SUMMARY:\n");
	(void) fprintf(stderr,"\tTotal DRR_BEGIN records = %lld\n",
	    (u_longlong_t)drr_record_count[DRR_BEGIN]);
	(void) fprintf(stderr,"\tTotal DRR_END records = %lld\n",
	    (u_longlong_t)drr_record_count[DRR_END]);
	(void) fprintf(stderr,"\tTotal DRR_OBJECT records = %lld\n",
	    (u_longlong_t)drr_record_count[DRR_OBJECT]);
	(void) fprintf(stderr,"\tTotal DRR_FREEOBJECTS records = %lld\n",
	    (u_longlong_t)drr_record_count[DRR_FREEOBJECTS]);
	(void) fprintf(stderr,"\tTotal DRR_WRITE records = %lld\n",
	    (u_longlong_t)drr_record_count[DRR_WRITE]);
	(void) fprintf(stderr,"\tTotal DRR_FREE records = %lld\n",
	    (u_longlong_t)drr_record_count[DRR_FREE]);
	(void) fprintf(stderr,"\tTotal DRR_SPILL records = %lld\n",
	    (u_longlong_t)drr_record_count[DRR_SPILL]);
	(void) fprintf(stderr,"\tTotal records = %lld\n",
	    (u_longlong_t)(drr_record_count[DRR_BEGIN] +
	    drr_record_count[DRR_OBJECT] +
	    drr_record_count[DRR_FREEOBJECTS] +
	    drr_record_count[DRR_WRITE] +
	    drr_record_count[DRR_FREE] +
	    drr_record_count[DRR_SPILL] +
	    drr_record_count[DRR_END]));
	(void) fprintf(stderr,"\tTotal write size = %lld (0x%llx)\n",
	    (u_longlong_t)total_write_size, (u_longlong_t)total_write_size);
	(void) fprintf(stderr,"\tTotal stream length = %lld (0x%llx)\n",
	    (u_longlong_t)total_stream_len, (u_longlong_t)total_stream_len);
	return (0);
}
