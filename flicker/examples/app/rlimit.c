/*
 * rlimit.c: rate limit pal driver
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
#include "rlimit.h"

#define SINIT_FILE      "/boot/sinit-current.bin"
#define PAL_FILE        "../pal/rlimit.bin"
#define BLOB_FILE       "rlimit.blob"
#define BLOB_BAK_FILE   "rlimit.blob.bak"

/* forward references */
static void print_output(void);
static int handle_results(void);
static int do_init(int secs, char *passphrase);
static int do_run(void);
static void userr(char *name);


int main(int ac, char **av)
{
    int secs;
    char *passphrase;
    int rslt = 0;

    /* pal inbuf is our outbuf */
    pm_init(outbuf, sizeof(outbuf), inbuf, sizeof(inbuf));

    if (ac < 2)
        userr(av[0]);

    if (strcmp(av[1], "init") == 0) {
        if (ac != 4 || (secs = atoi(av[2])) <= 0)
            userr(av[0]);
        passphrase = av[3];
        if ((rslt = do_init(secs, passphrase)) < 0)
            return -rslt;
    } else if (strcmp(av[1], "run") == 0) {
        if ((rslt = do_run()) < 0)
            return -rslt;
    } else {
        userr(av[0]);
    }

    if (callpal(SINIT_FILE, PAL_FILE, inbuf, sizeof(inbuf)-pm_avail(),
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
    fprintf(stderr, "Usage: %s [init <interval_secs> <passphrase> | run]\n", PAL_FILE);
    exit(1);
}

static void print_output()
{
    int nout;
    int *outp;

    outp = (int *)outbuf;
    nout = *outp++;
    while (nout--) {
        int type = *outp++;
        int size = *outp++;

        if (type == 1) {
            write(1, outp, size);
        }

        outp = (int *)((unsigned char *)outp + size);
    }
}

static int do_init(int secs, char *passphrase)
{
    int cmd = cmd_init;

    pm_append(tag_cmd, (char *)&cmd, sizeof(cmd));
    pm_append(tag_interval, (char *)&secs, sizeof(secs));
    pm_append(tag_passphrase, passphrase, strlen(passphrase));
    return 0;
}

static int do_run()
{
    int cmd = cmd_work;
    FILE *blobfile;
    int blobsize;
    unsigned char blob[512];

    pm_append(tag_cmd, (char *)&cmd, sizeof(cmd));

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

static int handle_results()
{
    char *outptr;
    FILE *blobfile;
    int blobsize;

    if (pm_get_addr(tag_rslt, &outptr) < 0) {
        fprintf(stderr, "no result from pal\n");
        return -1;
    }

    printf("result code from pal: %d\n", *(int *)outptr);

    if ((blobsize = pm_get_addr(tag_blob, &outptr)) < 0)
        return;

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
