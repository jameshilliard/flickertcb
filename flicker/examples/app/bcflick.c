/*
 * bcflick.c: bitcoin interface to flicker pal
 *
 * Copyright (C) 2012 Hal Finney
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include "callpal.h"
#include "bitcoin.h"

#define PAL_FILE        "%s/bcflick.bin"
#define BLOB_FILE       "%s/bcflick.blob"

unsigned char blob[10000];

/* forward references */
static void print_output(void);
static int handle_results(const char *datadir);
static int get_blob(const char *datadir);
static int check_iv(const unsigned char *iv);


int flicker_init(unsigned char *key, int keylen, int daylimit, const char *datadir)
{
    int cmd = cmd_init;
    char palfile[PATH_MAX];
    int rslt;

    /* pal inbuf is our outbuf */
    pm_init(outbuf, sizeof(outbuf), inbuf, sizeof(inbuf));

    sprintf(palfile, PAL_FILE, datadir);

    pm_append(tag_cmd, (char *)&cmd, sizeof(cmd));
    pm_append(tag_daylimit, (char *)&daylimit, sizeof(daylimit));
    pm_append(tag_key, key, 32);

    if (callpal(palfile, inbuf, sizeof(inbuf)-pm_avail(),
                outbuf, sizeof(outbuf)) < 0) {
        fprintf(stderr, "pal call failed for %s\n", palfile);
        return -2;
    }
    
    print_output();
    if ((rslt = handle_results(datadir)) < 0)
        return rslt;

    return rslt;
}

int flicker_encrypt(unsigned char *ctext, unsigned char const *ptext, unsigned ptsize,
            unsigned char const *iv, const char *datadir)
{
    int cmd = cmd_encrypt;
    int ctextlen;
    char *outptr;
    char palfile[PATH_MAX];
    int rslt;
    static int cnt;

    printf("flicker_encrypt called %d times\n", ++cnt);

    sprintf(palfile, PAL_FILE, datadir);

    /* pal inbuf is our outbuf */
    pm_init(outbuf, sizeof(outbuf), inbuf, sizeof(inbuf));

    if ((rslt = get_blob(datadir)) < 0)
        return rslt;
    pm_append(tag_cmd, (char *)&cmd, sizeof(cmd));
    pm_append(tag_iv, (char *)iv, 16);
    pm_append(tag_plaintext, (char *)ptext, ptsize);

    if (callpal(palfile, inbuf, sizeof(inbuf)-pm_avail(),
                outbuf, sizeof(outbuf)) < 0) {
        fprintf(stderr, "pal call failed for %s\n", palfile);
        return -2;
    }
    
    print_output();
    if ((rslt = handle_results(datadir)) < 0)
        return rslt;

    if ((ctextlen = pm_get_addr(tag_ciphertext, &outptr)) <  0)
        return -1;
    memcpy(ctext, outptr, ctextlen);

    check_iv(iv);

    return ctextlen;
}

int flicker_keygen(int compressed, unsigned char *ctext, unsigned char *pk, const char *datadir)
{
    int cmd = compressed ? cmd_keygen_comp : cmd_keygen_uncomp;
    int ctextlen;
    int pklen;
    char *outptr;
    char palfile[PATH_MAX];
    int rslt;
    static int cnt;

    printf("flicker_keygen called %d times\n", ++cnt);

    sprintf(palfile, PAL_FILE, datadir);

    /* pal inbuf is our outbuf */
    pm_init(outbuf, sizeof(outbuf), inbuf, sizeof(inbuf));

    if ((rslt = get_blob(datadir)) < 0)
        return rslt;
    pm_append(tag_cmd, (char *)&cmd, sizeof(cmd));

    if (callpal(palfile, inbuf, sizeof(inbuf)-pm_avail(),
                outbuf, sizeof(outbuf)) < 0) {
        fprintf(stderr, "pal call failed for %s\n", palfile);
        return -2;
    }
    
    print_output();
    if ((rslt = handle_results(datadir)) < 0)
        return rslt;

    if ((ctextlen = pm_get_addr(tag_ciphertext, &outptr)) <  0)
        return -1;
    memcpy(ctext, outptr, ctextlen);

    if ((pklen = pm_get_addr(tag_pk, &outptr)) <  0)
        return -1;
    memcpy(pk, outptr, pklen);

    return ctextlen;
}

int flicker_decrypt(unsigned char *ptext, unsigned char const *ctext, unsigned ctsize,
            unsigned char const *iv, const char *datadir)
{
    int cmd = cmd_decrypt;
    int ptextlen;
    int delay;
    char palfile[PATH_MAX];
    char *outptr;
    int rslt;

    /* pal inbuf is our outbuf */
    pm_init(outbuf, sizeof(outbuf), inbuf, sizeof(inbuf));

    sprintf(palfile, PAL_FILE, datadir);

    if ((rslt = get_blob(datadir)) < 0)
        return rslt;
    pm_append(tag_cmd, (char *)&cmd, sizeof(cmd));
    pm_append(tag_iv, (char *)iv, 16);
    pm_append(tag_ciphertext, (char *)ctext, ctsize);

    if (callpal(palfile, inbuf, sizeof(inbuf)-pm_avail(),
                outbuf, sizeof(outbuf)) < 0) {
        fprintf(stderr, "pal call failed for %s\n", palfile);
        return -2;
    }
    
    print_output();

    if (pm_get_addr(tag_delay, &outptr) > 0) {
        delay = *(int *)outptr;
        printf("retry in %d seconds\n", delay);
        return -1;
    }

    if ((rslt = handle_results(datadir)) < 0)
        return rslt;

    if ((ptextlen = pm_get_addr(tag_plaintext, &outptr)) <  0)
        return -1;
    memcpy(ptext, outptr, ptextlen);

    check_iv(iv);

    return ptextlen;
}

static int get_blob(const char *datadir)
{
    FILE *blobfile;
    int blobsize;
    char blobfilename[PATH_MAX];

    sprintf(blobfilename, BLOB_FILE, datadir);

    if ((blobfile = fopen(blobfilename, "rb")) == NULL) {
        fprintf(stderr, "unable to open blob file %s\n", blobfilename);
        return -1;
    }

    if ((blobsize = fread(blob, 1, sizeof(blob), blobfile)) == sizeof(blob)) {
        fprintf(stderr, "blob file too large\n");
        return -1;
    }

    fclose(blobfile);

    pm_append(tag_blob, (char *)blob, blobsize);
    return 0;
}

static void print_output()
{
    int nout;
    int *outp;
    unsigned long long ts, pts=0;

    outp = (int *)outbuf;
    nout = *outp++;
    while (nout--) {
        int type = *outp++;
        int size = *outp++;

        setlocale(LC_NUMERIC, "en_GB.utf8");

        if (type == 1) {
            fwrite(outp, 1, size, stdout);
#if 0
        } else if (type == 2) {
            ts = *(unsigned long long *)outp;
            printf(":%'13lld  ", (pts==0)?0ll:(ts-pts));
            fwrite((char *)outp+sizeof(long long), 1, size-sizeof(long long), stdout);
            printf("\n");
            pts = ts;
#endif
        }
        outp = (int *)((unsigned char *)outp + size);
    }
}

static int handle_results(const char *datadir)
{
    char *outptr;
    FILE *blobfile;
    int blobsize;
    int ptextlen, ctextlen;
    char blobfilename[PATH_MAX];
    int rslt;

    if (pm_get_addr(tag_rslt, &outptr) < 0) {
        fprintf(stderr, "no result from pal\n");
        return -1;
    }

    rslt = *(int *)outptr;
    printf("result code from pal: %d\n", rslt);

#if 0
    ptextlen = pm_get_addr(tag_plaintext, &outptr);
    ctextlen = pm_get_addr(tag_ciphertext, &outptr);
 
    if (ptextlen > 0)
        printf("plaintext:\n");
 
    if (ctextlen > 0)
        printf("ciphertext:\n");

    if (ptextlen > 0 || ctextlen > 0) {
        int i;
        for (i=0; i<((ctextlen>0)?ctextlen:ptextlen); i++)
            printf("%02x", ((unsigned char *)outptr)[i]);
        printf("\n");
    }
#endif

    sprintf(blobfilename, BLOB_FILE, datadir);

    if ((blobsize = pm_get_addr(tag_blob, &outptr)) < 0)
        return rslt;

    if ((blobfile = fopen(blobfilename, "wb")) == NULL) {
        fprintf(stderr, "unable to open for writing blob file %s\n", blobfilename);
        return -1;
    }

    if (fwrite(outptr, 1, blobsize, blobfile) != blobsize) {
        fprintf(stderr, "unable to write blob file\n");
        return -1;
    }

    fclose(blobfile);

    return rslt;
}


static int check_iv(const unsigned char *iv)
{
    unsigned char md[32];
    unsigned char ivv[32];
    unsigned char *pkptr;
    int pklen;

    if ((pklen = pm_get_addr(tag_pk, (char **)&pkptr)) <  0)
        return -1;
    if (pklen != 65)
        return -1;

     SHA256(pkptr, pklen, md);
     SHA256(md, sizeof(md), ivv);
     if (memcmp(iv, ivv, sizeof(ivv)) == 0) {
         printf("hash matches uncompressed\n");
         return 0;
     }

     pkptr[0] = 0x02;
     SHA256(pkptr, 33, md);
     SHA256(md, sizeof(md), ivv);
     if (memcmp(iv, ivv, sizeof(ivv)) == 0) {
         printf("hash matches compressed\n");
         return 0;
     }

     pkptr[0] = 0x03;
     SHA256(pkptr, 33, md);
     SHA256(md, sizeof(md), ivv);
     if (memcmp(iv, ivv, sizeof(ivv)) == 0) {
         printf("hash matches compressed\n");
         return 0;
     }

     printf("HASH DOESN'T MATCH\n");
     return -1;
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
