/*
 * callpal.c: load and run pal
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
#include </usr/include/string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <regex.h>
#include "callpal.h"

#define FLICKER_CTRL    "/sys/kernel/flicker/control"
#define FLICKER_DATA    "/sys/kernel/flicker/data"
#define CPU_CTRL        "/sys/devices/system/cpu"
#define SINIT_DIR       "/boot/"
#define SINIT_MATCH     "SINIT"

unsigned char inbuf[MAX_INPUT_PARAM_SIZE];
unsigned char outbuf[MAX_OUTPUT_PARAM_SIZE];

/* stub functions for params.c */
void printk(){}
void dump_bytes(){}

static int copyfile(int fd_from, int fd_to);
static int one_cpu(int turnon);
static int sinit_open();

int callpal(char *palname, void *inbuf, size_t inlen, void *outbuf, size_t outlen)
{
    int fd_ctrl=-1, fd_data=-1;
    int fd=-1;

    one_cpu(0);

    fd_ctrl = open(FLICKER_CTRL, O_WRONLY);
    fd_data = open(FLICKER_DATA, O_RDWR);
    if (fd_ctrl<0 || fd_data<0) {
        fprintf(stderr, "flicker is not running\n");
        goto error;
    }

    fd = sinit_open();
    if (fd >= 0) {
        write(fd_ctrl, "A", 1);
        if (copyfile(fd, fd_data) < 0) {
            fprintf(stderr, "error transferring sinit file\n");
            goto error;
        }
        close(fd);
        fd = -1;
        write(fd_ctrl, "a", 1);
    }

    fd = open(palname, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "error opening file %s\n", palname);
        goto error;
    }

    write(fd_ctrl, "M", 1);
    lseek(fd_data, 0, SEEK_SET);
    if (copyfile(fd, fd_data) < 0) {
        fprintf(stderr, "error transferring file %s\n", palname);
        goto error;
    }
    close(fd);
    fd = -1;
    write(fd_ctrl, "m", 1);

    write(fd_ctrl, "I", 1);
    lseek(fd_data, 0, SEEK_SET);
    while (inlen > 0) {
        int n = (inlen > PAGE_SIZE) ? PAGE_SIZE : inlen;
        if (write(fd_data, inbuf, n) < n) {
            fprintf(stderr, "error transferring input data\n");
            goto error;
        }
        inbuf += n;
        inlen -= n;
    }
    write(fd_ctrl, "i", 1);

    /* go */
    write(fd_ctrl, "G", 1);

    lseek(fd_data, 0, SEEK_SET);
    while (outlen > 0) {
        int n = (outlen > PAGE_SIZE) ? PAGE_SIZE : outlen;
        if (read(fd_data, outbuf, n) < n) {
            fprintf(stderr, "error transferring output data\n");
            goto error;
        }
        outbuf += n;
        outlen -= n;
    }

    close(fd_ctrl); close(fd_data);
    one_cpu(1);
    return 0;

error:
    if (fd_ctrl >= 0)
        close(fd_ctrl);
    if (fd_data >= 0)
        close(fd_data);
    if (fd >= 0)
        close(fd);
    one_cpu(1);
    return -1;
}


static int copyfile(int fd_from, int fd_to)
{
    unsigned char buf[PAGE_SIZE];
    int n;

    while ((n = read(fd_from, buf, sizeof(buf))) > 0) {
        int nn;
        if ((nn=write(fd_to, buf, n)) < n)
            return -1;
    }
    
    if (n < 0)
        return -1;
    return 0;
}

static int one_cpu(int turnon)
{
    DIR *dir;
    struct dirent *dirent;
    int cpunum;
    int fd;
    char new_state = turnon ? '1' : '0';
    char cur_state;
    char cpu_online[sizeof(CPU_CTRL)+30];

    dir = opendir(CPU_CTRL);
    if (dir == NULL) {
        fprintf(stderr, "one_cpu error\n");
        return -1;
    }

    while ((dirent = readdir(dir)) != NULL) {
        if (sscanf(dirent->d_name, "cpu%d", &cpunum) == 1
                && cpunum > 0) {
            sprintf(cpu_online, CPU_CTRL "/cpu%d/online", cpunum);
            if ((fd = open(cpu_online, O_RDWR)) < 0) {
                fprintf(stderr, "error opening %s\n", cpu_online);
                return -1;
            }

            if (read(fd, &cur_state, 1) != 1) {
                fprintf(stderr, "error reading %s\n", cpu_online);
                close(fd);
                return -1;
            }

            if (cur_state == new_state) {
                close(fd);
                continue;
            }

            if (write(fd, &new_state, 1) != 1) {
                fprintf(stderr, "error writing %s\n", cpu_online);
                close(fd);
                return -1;
            }

            lseek(fd, 0, SEEK_SET);
            if (read(fd, &cur_state, 1) != 1) {
                fprintf(stderr, "error reading %s\n", cpu_online);
                close(fd);
                return -1;
            }

            if (cur_state != new_state) {
                fprintf(stderr, "error changing state for %s\n", cpu_online);
                close(fd);
                return -1;
            }
            close(fd);
        }
    }

    closedir(dir);
    return 0;
}

static int sinit_open()
{
    DIR *dir;
    struct dirent *dirent;
    int fd = -1;
    char fname[PATH_MAX];
    regex_t regex;

    dir = opendir(SINIT_DIR);
    if (dir == NULL)
        return -1;

    regcomp(&regex, SINIT_MATCH, REG_NOSUB);
    while ((dirent = readdir(dir)) != NULL) {
        if (regexec(&regex, dirent->d_name, 0, 0, 0) == 0) {
            strcpy(fname, SINIT_DIR);
            strncat(fname, dirent->d_name, sizeof(fname) - strlen(fname) - 1);
            if ((fd = open(fname, O_RDONLY)) >= 0) {
                break;
            }
        }
    }

    regfree(&regex);
    closedir(dir);
    return fd;
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
