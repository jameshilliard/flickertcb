/*
 * noio.c: driver for simple pals without i/o
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
#include <stdarg.h>
#include "params.h"

#define SINIT_FILE  "/boot/sinit-current.bin"

unsigned char inbuf[MAX_OUTPUT_PARAM_SIZE];
unsigned char outbuf[MAX_OUTPUT_PARAM_SIZE];

extern int callpal(char *sinitname, char *palname, void *inbuf, size_t inlen,
            void *outbuf, size_t outlen);

static void print_output(void);

int main(int ac, char **av)
{
    char *pal;

    if (ac != 2) {
        fprintf(stderr, "Usage: %s palfile\n", av[0]);
       return 1;
    }
    pal = av[1];

    if (callpal(SINIT_FILE, pal, inbuf, sizeof(int), outbuf, sizeof(outbuf)) < 0) {
        fprintf(stderr, "pal call failed for %s\n", pal);
        return 2;
    }
    
    print_output();

    return 0;
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


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
