/*
 * bitcoin.c: prepare and test bitcoin support
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

#define PAL_FILE        "../pal/bcflick.bin"
#define BLOB_FILE       "bitcoin.blob"
#define BLOB_BAK_FILE   "bitcoin.blob.bak"

unsigned char blob[10000];

/* forward references */
static void print_output(void);
static int handle_results(void);
static int do_init(int daylimit, unsigned char *key);
static int do_encrypt(unsigned char *iv, unsigned char *ptext, int ptextlen);
static int do_decrypt(unsigned char *iv, unsigned char *ctext, int ctextlen);
static void userr(char *name);
static int scan_hex(char *s, unsigned char *buf);


int main(int ac, char **av)
{
    int daylimit;
    unsigned char key[32];
    int rslt = 0;

    /* pal inbuf is our outbuf */
    pm_init(outbuf, sizeof(outbuf), inbuf, sizeof(inbuf));

    if (ac < 2)
        userr(av[0]);

    if (strcmp(av[1], "init") == 0) {
        int i;
        char *hexkey;

        if (ac != 4 || (daylimit = atoi(av[2])) <= 0)
            userr(av[0]);
        hexkey = av[3];
        if (strlen(hexkey) != 64)
            userr(av[0]);
        if(scan_hex(hexkey, key) < 0)
            userr(av[0]);
        if ((rslt = do_init(daylimit, key)) < 0)
            return -rslt;
    } else if (strcmp(av[1], "encrypt") == 0
            || strcmp(av[1], "decrypt") == 0) {
        char *hexiv;
        char *hextext;
        int textlen;
        unsigned char iv[16];
        unsigned char *text;

        if (ac != 4)
            userr(av[0]);
        hexiv = av[2];
        hextext = av[3];
        if (strlen(hexiv) != 32)
            userr(av[0]);
        if(scan_hex(hexiv, iv) < 0)
            userr(av[0]);
        textlen = strlen(hextext)/2;
        text = malloc(textlen);
        if(scan_hex(hextext, text) < 0)
            userr(av[0]);
        if (strcmp(av[1], "encrypt") == 0) {
            if ((rslt = do_encrypt(iv, text, textlen)) < 0)
                return -rslt;
        } else {
            if ((rslt = do_decrypt(iv, text, textlen)) < 0)
                return -rslt;
        }
    } else {
        userr(av[0]);
    }

    if (callpal(PAL_FILE, inbuf, sizeof(inbuf)-pm_avail(),
                outbuf, sizeof(outbuf)) < 0) {
        fprintf(stderr, "pal call failed for %s\n", PAL_FILE);
        return 2;
    }
    
    print_output();
    if ((rslt = handle_results()) < 0)
        return -rslt;

    return 0;
}

static void userr(char *name)
{
    fprintf(stderr,
            "Usage: %s [init <daylimit> <64-char-key>\n"
            "\t| encrypt <32-char-iv> <plaintext>\n"
            "\t| decrypt <32-char-iv> <ciphertext>]\n", PAL_FILE);
    exit(1);
}

static int scan_hex(char *s, unsigned char *buf)
{
    int i, len=strlen(s)/2;

    for (i=0; i<len; i++) {
        if (sscanf(s+2*i, "%2hhx", buf+i) != 1)
            return -1;
    }
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
        } else if (type == 2) {
            ts = *(unsigned long long *)outp;
            printf(":%'13lld  ", (pts==0)?0ll:(ts-pts));
            fwrite((char *)outp+sizeof(long long), 1, size-sizeof(long long), stdout);
            printf("\n");
            pts = ts;
        }
        outp = (int *)((unsigned char *)outp + size);
    }
}

static int do_init(int daylimit, unsigned char *key)
{
    int cmd = cmd_init;

    pm_append(tag_cmd, (char *)&cmd, sizeof(cmd));
    pm_append(tag_daylimit, (char *)&daylimit, sizeof(daylimit));
    pm_append(tag_key, key, 32);
    return 0;
}

static int do_encrypt(unsigned char *iv, unsigned char *ptext, int ptextlen)
{
    int cmd = cmd_encrypt;
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

    pm_append(tag_cmd, (char *)&cmd, sizeof(cmd));
    pm_append(tag_iv, (char *)iv, 16);
    pm_append(tag_plaintext, (char *)ptext, ptextlen);

    return 0;
}

static int do_decrypt(unsigned char *iv, unsigned char *ctext, int ctextlen)
{
    int cmd = cmd_decrypt;
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

    pm_append(tag_cmd, (char *)&cmd, sizeof(cmd));
    pm_append(tag_iv, (char *)iv, 16);
    pm_append(tag_ciphertext, (char *)ctext, ctextlen);

    return 0;
}

static int handle_results()
{
    char *outptr;
    FILE *blobfile;
    int blobsize;
    int ptextlen, ctextlen;

    if (pm_get_addr(tag_rslt, &outptr) < 0) {
        fprintf(stderr, "no result from pal\n");
        return -1;
    }

    printf("result code from pal: %d\n", *(int *)outptr);

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
        return 0;

    rename(BLOB_FILE, BLOB_BAK_FILE);

    if ((blobfile = fopen(BLOB_FILE, "wb")) == NULL) {
        fprintf(stderr, "unable to open for writing blob file %s\n", BLOB_FILE);
        return -1;
    }

    if (fwrite(outptr, 1, blobsize, blobfile) != blobsize) {
        fprintf(stderr, "unable to write blob file\n");
        return -1;
    }

    fclose(blobfile);

    return 0;
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
