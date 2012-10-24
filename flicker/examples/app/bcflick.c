/*
 * bcflick.c: bitcoin interface to flicker pal
 *
 * Copyright (C) 2006-2011 Jonathan M. McCune
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
#include "callpal.h"
#include "bitcoin.h"

#define SINIT_FILE      "/boot/sinit-current.bin"
#define PAL_FILE        "../pal/bitcoin.bin"
#define BLOB_FILE       "bcflick.blob"
#define SECONDS         300

unsigned char blob[10000];

/* forward references */
static void print_output(void);
static int handle_results(void);
static int get_blob(void);


int flicker_init(unsigned char *key, int keylen)
{
    int cmd = cmd_init;
    int secs = SECONDS;
    int rslt;

    /* pal inbuf is our outbuf */
    pm_init(outbuf, sizeof(outbuf), inbuf, sizeof(inbuf));

    pm_append(tag_cmd, (char *)&cmd, sizeof(cmd));
    pm_append(tag_interval, (char *)&secs, sizeof(secs));
    pm_append(tag_key, key, 32);

    if (callpal(SINIT_FILE, PAL_FILE, inbuf, sizeof(inbuf)-pm_avail(),
                outbuf, sizeof(outbuf)) < 0) {
        fprintf(stderr, "pal call failed for %s\n", PAL_FILE);
        return -2;
    }
    
    print_output();
    if ((rslt = handle_results()) < 0)
        return rslt;

    return rslt;
}

int flicker_encrypt(unsigned char *ctext, unsigned char const *ptext, unsigned ptsize,
            unsigned char const *iv)
{
    int cmd = cmd_encrypt;
    int ctextlen;
    char *outptr;
    int rslt;
    static int cnt;

    printf("flicker_encrypt called %d times\n", ++cnt);

    /* pal inbuf is our outbuf */
    pm_init(outbuf, sizeof(outbuf), inbuf, sizeof(inbuf));

    if ((rslt = get_blob()) < 0)
        return rslt;
    pm_append(tag_cmd, (char *)&cmd, sizeof(cmd));
    pm_append(tag_iv, (char *)iv, 16);
    pm_append(tag_plaintext, (char *)ptext, ptsize);

    if (callpal(SINIT_FILE, PAL_FILE, inbuf, sizeof(inbuf)-pm_avail(),
                outbuf, sizeof(outbuf)) < 0) {
        fprintf(stderr, "pal call failed for %s\n", PAL_FILE);
        return -2;
    }
    
    print_output();
    if ((rslt = handle_results()) < 0)
        return rslt;

    if (rslt != 0)
        return -100 - rslt;

    if ((ctextlen = pm_get_addr(tag_ciphertext, &outptr)) <  0)
        return -1;

    memcpy(ctext, outptr, ctextlen);

    return ctextlen;
}

int flicker_decrypt(unsigned char *ptext, unsigned char const *ctext, unsigned ctsize,
            unsigned char const *iv)
{
    int cmd = cmd_decrypt;
    int ptextlen;
    int delay;
    char *outptr;
    int rslt;

    /* pal inbuf is our outbuf */
    pm_init(outbuf, sizeof(outbuf), inbuf, sizeof(inbuf));

    for (;;) {
            if ((rslt = get_blob()) < 0)
            return rslt;
        pm_append(tag_cmd, (char *)&cmd, sizeof(cmd));
        pm_append(tag_iv, (char *)iv, 16);
        pm_append(tag_ciphertext, (char *)ctext, ctsize);

        if (callpal(SINIT_FILE, PAL_FILE, inbuf, sizeof(inbuf)-pm_avail(),
                    outbuf, sizeof(outbuf)) < 0) {
            fprintf(stderr, "pal call failed for %s\n", PAL_FILE);
            return -2;
        }
        
        print_output();
        if ((rslt = handle_results()) < 0)
            return rslt;

        if (pm_get_addr(tag_delay, &outptr) < 0)
            break;

        delay = *(int *)outptr;

        fprintf(stderr, "sleeping for %d seconds\n", delay);
        sleep(delay);
    }

    if (rslt != 0)
        return -100 - rslt;

    if ((ptextlen = pm_get_addr(tag_plaintext, &outptr)) <  0)
        return -1;

    memcpy(ptext, outptr, ptextlen);

    return ptextlen;
}

static int get_blob()
{
    FILE *blobfile;
    int blobsize;

    if ((blobfile = fopen(BLOB_FILE, "rb")) == NULL) {
        fprintf(stderr, "unable to open blob file %s\n", BLOB_FILE);
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

        if (type == 1) {
            fwrite(outp, 1, size, stdout);
#if 0
        } else if (type == 2) {
            ts = *(unsigned long long *)outp;
            printf(":%12lld  ", (pts==0)?0ll:(ts-pts));
            fwrite((char *)outp+sizeof(long long), 1, size-sizeof(long long), stdout);
            printf("\n");
            pts = ts;
#endif
        }
        outp = (int *)((unsigned char *)outp + size);
    }
}

static int handle_results()
{
    char *outptr;
    FILE *blobfile;
    int blobsize;
    int ptextlen, ctextlen;
    int rslt;

    if (pm_get_addr(tag_rslt, &outptr) < 0) {
        fprintf(stderr, "no result from pal\n");
        return -1;
    }

    rslt = *(int *)outptr;
    printf("result code from pal: %d\n", rslt);

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

    if ((blobsize = pm_get_addr(tag_blob, &outptr)) < 0)
        return rslt;

    if ((blobfile = fopen(BLOB_FILE, "wb")) == NULL) {
        fprintf(stderr, "unable to open for writing blob file %s\n", BLOB_FILE);
        return -1;
    }

    if (fwrite(outptr, 1, blobsize, blobfile) != blobsize) {
        fprintf(stderr, "unable to write blob file\n");
        return -1;
    }

    fclose(blobfile);

    return rslt;
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
