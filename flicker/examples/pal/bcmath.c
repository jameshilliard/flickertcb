/*
 * bcmath.c: math for bitcoin
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

#include "tommath.h"

#include <stdarg.h>
#include "malloc.h"
#include "printk.h"
#include "params.h"
#include "string.h"
#include "util.h"


#define PBITS       256
#define PLEN        (PBITS/8)
#define WINDOW      5
#define WINMASK     ((1<<WINDOW)-1)
#define NWINS       ((PBITS+WINDOW-1)/WINDOW)


typedef struct {
    mp_int _x, _y;
    mp_int *x, *y;
} ecpoint;


/* 2**(5*i) * G */
static uint8_t G[NWINS][2][PLEN] = {
   {{0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,0xce,0x87,0x0b,0x07,
     0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98,},
    {0x48,0x3a,0xda,0x77,0x26,0xa3,0xc4,0x65,0x5d,0xa4,0xfb,0xfc,0x0e,0x11,0x08,0xa8,
     0xfd,0x17,0xb4,0x48,0xa6,0x85,0x54,0x19,0x9c,0x47,0xd0,0x8f,0xfb,0x10,0xd4,0xb8,}
   },
   {{0xd3,0x01,0x99,0xd7,0x4f,0xb5,0xa2,0x2d,0x47,0xb6,0xe0,0x54,0xe2,0xf3,0x78,0xce,
     0xda,0xcf,0xfc,0xb8,0x99,0x04,0xa6,0x1d,0x75,0xd0,0xdb,0xd4,0x07,0x14,0x3e,0x65,},
    {0x95,0x03,0x8d,0x9d,0x0a,0xe3,0xd5,0xc3,0xb3,0xd6,0xde,0xc9,0xe9,0x83,0x80,0x65,
     0x1f,0x76,0x0c,0xc3,0x64,0xed,0x81,0x96,0x05,0xb3,0xff,0x1f,0x24,0x10,0x6a,0xb9,}
   },
   {{0x24,0x1f,0xeb,0xb8,0xe2,0x3c,0xbd,0x77,0xd6,0x64,0xa1,0x8f,0x66,0xad,0x62,0x40,
     0xaa,0xec,0x6e,0xcd,0xc8,0x13,0xb0,0x88,0xd5,0xb9,0x01,0xb2,0xe2,0x85,0x13,0x1f,},
    {0x51,0x33,0x78,0xd9,0xff,0x94,0xf8,0xd3,0xd6,0xc4,0x20,0xbd,0x13,0x98,0x1d,0xf8,
     0xcd,0x50,0xfd,0x0f,0xbd,0x0c,0xb5,0xaf,0xab,0xb3,0xe6,0x6f,0x27,0x50,0x02,0x6d,}
   },
   {{0x4a,0x4a,0x6d,0xc9,0x7a,0xc7,0xc8,0xb8,0xad,0x79,0x5d,0xbe,0xbc,0xb9,0xdc,0xff,
     0x72,0x90,0xb6,0x8a,0x5e,0xf7,0x4e,0x56,0xab,0x5e,0xdd,0xe0,0x1b,0xce,0xd7,0x75,},
    {0x52,0x99,0x11,0xb0,0x16,0x63,0x1e,0x72,0x94,0x3e,0xf9,0xf7,0x39,0xc0,0xf4,0x57,
     0x1d,0xe9,0x0c,0xdb,0x42,0x47,0x42,0xac,0xb2,0xbf,0x8f,0x68,0xa7,0x8d,0xd6,0x6d,}
   },
   {{0x8b,0x4b,0x5f,0x16,0x5d,0xf3,0xc2,0xbe,0x8c,0x62,0x44,0xb5,0xb7,0x45,0x63,0x88,
     0x43,0xe4,0xa7,0x81,0xa1,0x5b,0xcd,0x1b,0x69,0xf7,0x9a,0x55,0xdf,0xfd,0xf8,0x0c,},
    {0x4a,0xad,0x0a,0x6f,0x68,0xd3,0x08,0xb4,0xb3,0xfb,0xd7,0x81,0x3a,0xb0,0xda,0x04,
     0xf9,0xe3,0x36,0x54,0x61,0x62,0xee,0x56,0xb3,0xef,0xf0,0xc6,0x5f,0xd4,0xfd,0x36,}
   },
   {{0x57,0xef,0xa7,0x86,0x43,0x7b,0x74,0x4d,0x34,0x3d,0x7d,0xc4,0x57,0x73,0xa3,0xc6,
     0x2d,0x24,0x0a,0x43,0x07,0x98,0x49,0x07,0x1f,0xd3,0x83,0xd6,0x0c,0xa0,0x30,0xd5,},
    {0xd7,0x12,0xdb,0x0b,0xd1,0xb4,0x85,0x18,0x89,0x36,0x27,0xc9,0x28,0xde,0x03,0xec,
     0x68,0x9b,0x6d,0x2a,0xe5,0xe9,0x97,0x4a,0xb0,0x7a,0xb4,0x42,0x74,0xb0,0x2f,0x9e,}
   },
   {{0xe1,0xef,0xb9,0xcd,0x05,0xad,0xc6,0x3b,0xcc,0xe1,0x08,0x31,0xd9,0x53,0x8c,0x47,
     0x9c,0xf1,0xd0,0x5f,0xef,0xdd,0x08,0xb2,0x44,0x8d,0x70,0x42,0x2e,0xde,0x45,0x4c,},
    {0x0e,0xcb,0x45,0x30,0xd8,0xaf,0x9b,0xe7,0xb0,0x15,0x4c,0x1f,0xfe,0x47,0x71,0x23,
     0x46,0x4e,0x32,0x44,0xa7,0xa2,0xd4,0xc6,0xad,0x9f,0xd2,0x33,0xa8,0x91,0x37,0x97,}
   },
   {{0xe7,0x47,0x33,0x3f,0xd7,0x5d,0x51,0x75,0x5a,0x0c,0xc9,0xf0,0xa7,0x28,0x70,0x84,
     0x65,0xa0,0x2c,0x58,0x77,0x37,0xa7,0xb8,0xb8,0xfa,0x1b,0x8b,0x4b,0xb2,0x62,0x9a,},
    {0xf2,0xaf,0xfe,0x01,0x45,0x07,0x0c,0x11,0x4c,0xc4,0x36,0x03,0x80,0x4c,0x25,0x81,
     0xc8,0x83,0x76,0xaa,0x6e,0x1a,0x96,0x9a,0x9f,0x8d,0x96,0x1a,0x69,0x46,0xf6,0xd6,}
   },
   {{0xfe,0xea,0x6c,0xae,0x46,0xd5,0x5b,0x53,0x0a,0xc2,0x83,0x9f,0x14,0x3b,0xd7,0xec,
     0x5c,0xf8,0xb2,0x66,0xa4,0x1d,0x6a,0xf5,0x2d,0x5e,0x68,0x8d,0x90,0x94,0x69,0x6d,},
    {0xe5,0x7c,0x6b,0x6c,0x97,0xdc,0xe1,0xba,0xb0,0x6e,0x4e,0x12,0xbf,0x3e,0xcd,0x5c,
     0x98,0x1c,0x89,0x57,0xcc,0x41,0x44,0x2d,0x31,0x55,0xde,0xbf,0x18,0x09,0x00,0x88,}
   },
   {{0x4d,0xba,0xcd,0x36,0x5f,0xa1,0xef,0x58,0x7c,0x0c,0x0c,0xfa,0xaf,0x00,0xd8,0x71,
     0x8b,0xbd,0x9f,0x35,0xcc,0xea,0x5a,0x83,0x5e,0xe3,0xcc,0x82,0x1f,0xe7,0x41,0xc9,},
    {0x16,0xc3,0x54,0x0e,0x8a,0x51,0x89,0x2e,0x7f,0xdc,0xfd,0x59,0xe8,0x38,0x29,0x9d,
     0x0c,0xc3,0x84,0xa0,0x9f,0xc0,0x53,0x5f,0x60,0xbe,0x10,0xf8,0x33,0x8e,0xb6,0x23,}
   },
   {{0xf5,0xf0,0xe0,0x43,0x76,0x21,0xd4,0x39,0xca,0x71,0xf5,0xc1,0xb7,0x61,0x55,0xd6,
     0xd3,0xa6,0x1a,0x83,0xd3,0xc2,0x0c,0x6e,0xe3,0x09,0xd7,0x55,0xe3,0x15,0x56,0x5b,},
    {0x6b,0x9f,0x4e,0x62,0xbe,0x5a,0x05,0x2b,0xf6,0x21,0x89,0x16,0x0d,0xf7,0x10,0x1a,
     0xa5,0xbf,0x61,0xbf,0x3e,0xd7,0xe4,0x0a,0x67,0x84,0x30,0xaf,0xdd,0x2e,0xcc,0x82,}
   },
   {{0x23,0x80,0xc0,0x9c,0x7f,0x3a,0xea,0xe5,0x7c,0x46,0xe0,0x73,0x95,0xae,0xb0,0xdc,
     0x94,0x4d,0xba,0xf2,0xb6,0x2a,0x9f,0x0c,0x5e,0x8a,0x64,0xad,0x6a,0xe7,0xd6,0x16,},
    {0x6f,0x8e,0x86,0x19,0x34,0x64,0x95,0x6a,0xf1,0x59,0x8a,0xef,0xd5,0x09,0xb0,0x9a,
     0x93,0xaf,0x92,0x14,0x8f,0x84,0x67,0x56,0x00,0x99,0xbe,0x48,0x16,0x1b,0xbc,0x1a,}
   },
   {{0x06,0xf9,0xd9,0xb8,0x03,0xec,0xf1,0x91,0x63,0x7c,0x73,0xa4,0x41,0x3d,0xfa,0x18,
     0x0f,0xdd,0xf8,0x4a,0x59,0x47,0xfb,0xc9,0xc6,0x06,0xed,0x86,0xc3,0xfa,0xc3,0xa7,},
    {0x7c,0x80,0xc6,0x8e,0x60,0x30,0x59,0xba,0x69,0xb8,0xe2,0xa3,0x0e,0x45,0xc4,0xd4,
     0x7e,0xa4,0xdd,0x2f,0x5c,0x28,0x10,0x02,0xd8,0x68,0x90,0x60,0x3a,0x84,0x21,0x60,}
   },
   {{0x8d,0x26,0x20,0x02,0x50,0xce,0xbd,0xae,0x12,0x0e,0xf3,0x1b,0x04,0xc8,0x0c,0xd5,
     0x0d,0x4c,0xdd,0xc8,0xea,0xdb,0xcf,0x29,0xfc,0x69,0x6d,0x32,0xc0,0xad,0xe4,0x62,},
    {0xeb,0xed,0x3b,0xb4,0x71,0x5b,0xf4,0x37,0xd3,0x1f,0x6f,0x2d,0xc3,0xee,0x36,0xba,
     0x1d,0x4a,0xfb,0x4e,0x72,0x67,0x8b,0x3a,0xd8,0xe0,0xa8,0xb9,0x0f,0x26,0x47,0x0c,}
   },
   {{0xa9,0x1d,0x1f,0x5c,0xee,0x87,0xb7,0xf3,0x08,0x1e,0x14,0x20,0x18,0xf8,0xaa,0xed,
     0x79,0x02,0x0d,0x47,0xec,0xfb,0xc8,0xd2,0xc7,0x17,0x09,0x23,0xe8,0xbe,0xe8,0xb6,},
    {0x74,0x8a,0x32,0x4e,0xe2,0xdf,0x8e,0xe1,0x5a,0x71,0x89,0xc8,0xdd,0xda,0xd3,0xb2,
     0xf8,0x00,0x56,0x9f,0x62,0x8c,0xb2,0x25,0x00,0x3d,0x16,0xaa,0x41,0x06,0x44,0xc1,}
   },
   {{0x10,0x74,0x60,0x52,0x0e,0xec,0x5c,0x74,0x16,0x83,0x32,0x9a,0x71,0x66,0x22,0xb0,
     0xb8,0x1c,0x03,0x20,0x08,0x07,0xde,0x97,0x36,0x86,0xf8,0x80,0x0b,0x18,0x8c,0xbb,},
    {0xab,0xe5,0xd4,0xc0,0x9a,0x21,0x59,0x8c,0x35,0x32,0x6b,0x9b,0x9c,0xf5,0x4a,0x11,
     0x24,0x2e,0x0d,0x74,0x8d,0xce,0x3d,0xa6,0x01,0xd7,0xb6,0x36,0x1f,0x27,0x21,0x24,}
   },
   {{0xe5,0x03,0x7d,0xe0,0xaf,0xc1,0xd8,0xd4,0x3d,0x83,0x48,0x41,0x4b,0xbf,0x41,0x03,
     0x04,0x3e,0xc8,0xf5,0x75,0xbf,0xdc,0x43,0x29,0x53,0xcc,0x8d,0x20,0x37,0xfa,0x2d,},
    {0x45,0x71,0x53,0x4b,0xaa,0x94,0xd3,0xb5,0xf9,0xf9,0x8d,0x09,0xfb,0x99,0x0b,0xdd,
     0xbd,0x5f,0x5b,0x03,0xec,0x48,0x1f,0x10,0xe0,0xe5,0xdc,0x84,0x1d,0x75,0x5b,0xda,}
   },
   {{0x0e,0xac,0x13,0x4c,0xa2,0x04,0x6b,0x8f,0x9c,0x8d,0xbd,0x30,0x4f,0xad,0x3f,0x3c,
     0x04,0x5e,0xbf,0xdb,0x4e,0xc6,0xed,0x3c,0xfe,0x09,0xae,0xe4,0x3e,0xd2,0xff,0x3e,},
    {0x49,0x63,0x0d,0xbe,0x79,0x35,0x9b,0x42,0x45,0xbf,0x10,0x3b,0xf2,0xb1,0x17,0x99,
     0xac,0x19,0xf6,0x96,0xb7,0xf2,0x13,0x76,0xe1,0x72,0x06,0x20,0x7d,0x21,0x09,0x88,}
   },
   {{0x46,0x27,0x6d,0x06,0x02,0xc5,0x66,0x8d,0xde,0xf6,0xe9,0x42,0x10,0xbb,0xc7,0xce,
     0x1f,0x90,0x1c,0x19,0xfe,0xd5,0xc9,0x70,0xe2,0x0f,0xcb,0xa1,0xd4,0x53,0x1d,0xbc,},
    {0x0e,0x0f,0x7f,0x24,0xd4,0x4c,0x75,0xb8,0x4a,0x29,0x22,0x87,0x57,0x0d,0xed,0x99,
     0x49,0x8b,0xad,0xfb,0xff,0xe1,0xbc,0x99,0xaf,0x87,0x30,0x09,0x96,0x86,0xb8,0xe2,}
   },
   {{0x32,0x7f,0x87,0x6c,0x93,0x65,0x25,0x55,0xfa,0x80,0xa0,0x54,0x96,0x8b,0x47,0x12,
     0x93,0x0d,0xc9,0x30,0x12,0xee,0x6b,0x8d,0xc1,0x02,0x63,0xed,0x3b,0x89,0xa7,0x62,},
    {0xb2,0xd4,0x04,0xea,0xb3,0x52,0x40,0x26,0xb0,0x99,0x69,0x25,0x5e,0x19,0x97,0xb9,
     0x75,0x53,0x50,0x70,0xfe,0xbd,0x7d,0xfe,0x9c,0x9f,0xd9,0x59,0xb9,0x20,0x33,0x01,}
   },
   {{0x76,0xe6,0x41,0x13,0xf6,0x77,0xcf,0x0e,0x10,0xa2,0x57,0x0d,0x59,0x99,0x68,0xd3,
     0x15,0x44,0xe1,0x79,0xb7,0x60,0x43,0x29,0x52,0xc0,0x2a,0x44,0x17,0xbd,0xde,0x39,},
    {0xc9,0x0d,0xdf,0x8d,0xee,0x4e,0x95,0xcf,0x57,0x70,0x66,0xd7,0x06,0x81,0xf0,0xd3,
     0x5e,0x2a,0x33,0xd2,0xb5,0x6d,0x20,0x32,0xb4,0xb1,0x75,0x2d,0x19,0x01,0xac,0x01,}
   },
   {{0x55,0x78,0x84,0x5e,0xcd,0x7c,0x03,0x74,0x35,0xb3,0x2a,0x69,0x92,0xe7,0xaa,0x94,
     0x64,0x71,0x97,0xea,0x49,0xb8,0xc9,0xe4,0xdd,0xaa,0xb0,0x78,0x46,0x62,0xab,0x1b,},
    {0xe6,0x1d,0x07,0x97,0x8b,0x6d,0xe2,0xc3,0xce,0xa6,0xd0,0xa5,0x1d,0x2a,0x40,0x53,
     0xf6,0x53,0xa7,0x74,0x6a,0x5d,0x64,0xde,0x31,0x6d,0x18,0xf3,0x05,0x6f,0x35,0x11,}
   },
   {{0xd9,0x9e,0x8e,0x9d,0xd9,0x63,0x8d,0x14,0x0e,0x9c,0xca,0x53,0x67,0x51,0x9f,0x86,
     0x1b,0x70,0x03,0xa0,0xd4,0x3f,0x02,0x4a,0x5f,0x1d,0x84,0xec,0x8d,0xb1,0xcb,0x3c,},
    {0x36,0xdc,0x19,0xad,0x1c,0xc0,0xa3,0xa7,0xa9,0x45,0xbb,0x32,0x1b,0xce,0xba,0x6e,
     0x62,0x86,0xfe,0xf8,0xff,0xc8,0x76,0x5c,0xd8,0x8a,0x29,0xe3,0x6b,0x86,0x37,0xa7,}
   },
   {{0x79,0x66,0x34,0xe3,0xf1,0xad,0x56,0xf0,0xfd,0xba,0x06,0x9d,0x9d,0x07,0xbc,0xe2,
     0xba,0x2f,0xd4,0xf3,0x73,0xdd,0xd3,0xba,0x77,0x77,0xbf,0x27,0x9f,0x10,0x48,0xda,},
    {0x4d,0x8e,0xe2,0xb6,0xcf,0xb2,0x0b,0x89,0x56,0xde,0x74,0x73,0x5a,0x79,0x27,0xf2,
     0x53,0x25,0x76,0xd8,0xcf,0xd7,0x48,0x62,0xe8,0xf9,0xbe,0x24,0xa1,0x06,0xcf,0x01,}
   },
   {{0xa3,0x01,0x69,0x7b,0xdf,0xcd,0x70,0x43,0x13,0xba,0x48,0xe5,0x1d,0x56,0x75,0x43,
     0xf2,0xa1,0x82,0x03,0x1e,0xfd,0x69,0x15,0xdd,0xc0,0x7b,0xbc,0xc4,0xe1,0x60,0x70,},
    {0x73,0x70,0xf9,0x1c,0xfb,0x67,0xe4,0xf5,0x08,0x18,0x09,0xfa,0x25,0xd4,0x0f,0x9b,
     0x17,0x35,0xdb,0xf7,0xc0,0xa1,0x1a,0x13,0x0c,0x0d,0x1a,0x04,0x1e,0x17,0x7e,0xa1,}
   },
   {{0x7e,0x2c,0xd4,0x0e,0xf8,0xc9,0x40,0x77,0xf4,0x4b,0x1d,0x15,0x48,0x42,0x5e,0x3d,
     0x7e,0x12,0x5b,0xe6,0x46,0x70,0x7b,0xad,0x28,0x18,0xb0,0xed,0xa7,0xdc,0x01,0x51,},
    {0x90,0x5b,0x75,0x08,0x2a,0xdc,0xfa,0xb3,0x82,0xa6,0x1a,0x8b,0x32,0x1e,0xf9,0x5d,
     0x88,0x9b,0xee,0x40,0xae,0xee,0x08,0x2c,0x9a,0x3b,0xc5,0x39,0x20,0x72,0x1e,0xc7,}
   },
   {{0x75,0x64,0x53,0x9e,0x85,0xd5,0x6f,0x85,0x37,0xd6,0x61,0x9e,0x1f,0x5c,0x5a,0xa7,
     0x8d,0x2a,0x3d,0xe0,0x88,0x9d,0x1d,0x4e,0xe8,0xdb,0xcb,0x57,0x29,0xb6,0x20,0x26,},
    {0xc1,0xd6,0x85,0x41,0x37,0x49,0xb3,0xc6,0x52,0x31,0xdf,0x52,0x4a,0x72,0x29,0x25,
     0x68,0x4a,0xac,0xd9,0x54,0xb7,0x9f,0x33,0x41,0x72,0xc8,0xfa,0xda,0xce,0x0c,0xf3,}
   },
   {{0xf4,0x78,0x05,0x6d,0x9c,0x10,0x2c,0x1c,0xd0,0x6d,0x7b,0x1e,0x75,0x57,0x24,0x4c,
     0x6d,0x9c,0xda,0xc5,0x87,0x46,0x10,0xe9,0x4d,0x47,0x86,0xe1,0x06,0xde,0x12,0xc0,},
    {0x7f,0x09,0xe6,0x10,0xf3,0x3e,0x39,0x46,0xe6,0x80,0x95,0xe0,0x10,0x68,0x69,0x4c,
     0x26,0xc1,0x7e,0xf6,0x09,0xab,0x92,0xd7,0x69,0xa7,0x6c,0xe6,0xca,0x53,0x61,0xfe,}
   },
   {{0xe7,0xa2,0x6c,0xe6,0x9d,0xd4,0x82,0x9f,0x3e,0x10,0xce,0xc0,0xa9,0xe9,0x8e,0xd3,
     0x14,0x3d,0x08,0x4f,0x30,0x8b,0x92,0xc0,0x99,0x7f,0xdd,0xfc,0x60,0xcb,0x3e,0x41,},
    {0x2a,0x75,0x8e,0x30,0x0f,0xa7,0x98,0x4b,0x47,0x1b,0x00,0x6a,0x1a,0xaf,0xbb,0x18,
     0xd0,0xa6,0xb2,0xc0,0x42,0x0e,0x83,0xe2,0x0e,0x8a,0x94,0x21,0xcf,0x2c,0xfd,0x51,}
   },
   {{0xe5,0xd8,0xe8,0xf0,0xd9,0x82,0x3c,0x88,0xe4,0xd3,0x6f,0x73,0x01,0xf4,0x15,0x93,
     0xb6,0x89,0x05,0x76,0xbe,0x79,0xc2,0x11,0x25,0x3e,0xf3,0x75,0x03,0x3e,0xb5,0x1f,},
    {0x4d,0xc1,0xe9,0xb7,0x86,0x1e,0x3e,0x04,0xab,0xb1,0x6a,0x57,0xd8,0xfe,0xee,0xf0,
     0xe5,0x09,0xdc,0x46,0xd9,0xf0,0xf5,0x49,0x79,0xd5,0xbd,0x96,0x5a,0x62,0xa2,0xd9,}
   },
   {{0x41,0x54,0xb5,0x06,0xab,0x76,0x6f,0x42,0xfb,0xe3,0x7f,0x69,0x99,0x76,0xf8,0x4d,
     0xb8,0x9f,0x4f,0x2f,0x6b,0xed,0x98,0x32,0x5c,0x1a,0x0b,0x6e,0x32,0x6d,0xd4,0xe4,},
    {0x23,0xad,0x07,0x50,0x43,0xc5,0x98,0x88,0x94,0xc6,0xe4,0x4d,0x61,0x02,0x5f,0xf6,
     0x41,0x4e,0xa9,0xd9,0xd1,0xe2,0x2d,0xd4,0x6c,0x85,0x92,0x95,0x07,0x5d,0xed,0x1c,}
   },
   {{0xa6,0x5a,0x3a,0x01,0xdf,0x3b,0x5e,0xf2,0xe6,0x20,0xd4,0x31,0x00,0x49,0xfb,0xe1,
     0x4d,0x71,0x45,0x7f,0x19,0xd1,0xed,0x35,0xae,0xa3,0x9d,0x57,0x89,0x30,0x3f,0xdd,},
    {0x79,0x8e,0xa0,0x94,0x0c,0xff,0x5c,0x6f,0xb8,0xf4,0x3d,0x8d,0x90,0xed,0x2c,0x76,
     0x86,0x86,0x1d,0x02,0x4f,0xae,0xd3,0xca,0xda,0xd4,0x4a,0x8d,0x02,0xe6,0x87,0x03,}
   },
   {{0x9c,0x39,0x19,0xa8,0x4a,0x47,0x48,0x70,0xfa,0xed,0x8a,0x9c,0x1c,0xc6,0x60,0x21,
     0x52,0x34,0x89,0x05,0x4d,0x7f,0x03,0x08,0xcb,0xfc,0x99,0xc8,0xac,0x1f,0x98,0xcd,},
    {0xdd,0xb8,0x4f,0x0f,0x4a,0x4d,0xdd,0x57,0x58,0x4f,0x04,0x4b,0xf2,0x60,0xe6,0x41,
     0x90,0x53,0x26,0xf7,0x6c,0x64,0xc8,0xe6,0xbe,0x7e,0x5e,0x03,0xd4,0xfc,0x59,0x9d,}
   },
   {{0x67,0x73,0xfd,0x67,0x7c,0x52,0xe0,0x64,0x03,0x94,0x11,0x0a,0x46,0xdc,0x85,0xdf,
     0x7c,0x13,0x3f,0x8d,0xd4,0xa2,0x8e,0x66,0x18,0x99,0xca,0x5d,0x82,0xfd,0x54,0x5c,},
    {0x44,0x4e,0xb6,0xd8,0xcd,0x97,0x65,0x2f,0x0f,0x0f,0x25,0xc9,0xdd,0x2b,0x24,0x6b,
     0xea,0xd7,0x80,0xf5,0xa1,0xc6,0xcf,0x98,0xe8,0xc7,0xf0,0x34,0x94,0x7e,0xb1,0xae,}
   },
   {{0xa7,0xde,0x08,0x37,0x5b,0x87,0x45,0xad,0xf8,0xd6,0xe9,0xf9,0x76,0xf0,0x3b,0x20,
     0xe3,0x36,0x25,0xa0,0x5c,0xef,0x58,0x33,0x95,0x3e,0xd5,0x87,0x44,0xbf,0x7e,0xa0,},
    {0xa6,0x3d,0x96,0xb0,0x57,0xad,0xa5,0xe5,0x21,0x04,0xa0,0xb3,0x34,0x88,0x8e,0x9a,
     0x64,0x5a,0x47,0xc0,0xfe,0xbc,0x5a,0xa2,0xe0,0x4c,0x05,0x53,0x9b,0xbc,0xab,0xaa,}
   },
   {{0x02,0x18,0x34,0x3a,0xcb,0x9b,0xe5,0x68,0x33,0xa3,0x2e,0x59,0x4c,0x03,0xc3,0x9e,
     0x5b,0x19,0x11,0xc8,0x50,0x12,0x13,0x78,0x6f,0x63,0x76,0xdf,0xa3,0x96,0x20,0xe1,},
    {0xbe,0xa8,0x1d,0x48,0x97,0x0a,0x50,0xbe,0xaf,0x3f,0x24,0xfd,0x60,0x2f,0xbf,0xc0,
     0x44,0x32,0x99,0xa4,0x2f,0x43,0xc9,0xec,0x5e,0x01,0x99,0xf6,0x50,0x69,0x98,0xb5,}
   },
   {{0x85,0xd0,0xfe,0xf3,0xec,0x6d,0xb1,0x09,0x39,0x90,0x64,0xf3,0xa0,0xe3,0xb2,0x85,
     0x56,0x45,0xb4,0xa9,0x07,0xad,0x35,0x45,0x27,0xaa,0xe7,0x51,0x63,0xd8,0x27,0x51,},
    {0x1f,0x03,0x64,0x84,0x13,0xa3,0x8c,0x0b,0xe2,0x9d,0x49,0x6e,0x58,0x2c,0xf5,0x66,
     0x3e,0x87,0x51,0xe9,0x68,0x77,0x33,0x15,0x82,0xc2,0x37,0xa2,0x4e,0xb1,0xf9,0x62,}
   },
   {{0x29,0x82,0xdb,0xbc,0x5f,0x36,0x6c,0x9f,0x78,0xe2,0x9e,0xbb,0xec,0xb1,0xbb,0x22,
     0x3d,0xeb,0x5c,0x4e,0xe6,0x38,0xb4,0x58,0x3b,0xd3,0xa9,0xaf,0x31,0x49,0xf8,0xef,},
    {0xa6,0x1b,0x5b,0xe9,0xaf,0x66,0x22,0x0a,0xb9,0xfa,0x53,0x39,0xc7,0xb5,0xbc,0x9d,
     0x09,0x5d,0xb9,0x94,0x12,0xe3,0xed,0x84,0x56,0xe7,0x26,0xb0,0x16,0xc7,0xa2,0x48,}
   },
   {{0x48,0x97,0x3b,0x94,0x30,0x18,0xbf,0x12,0x47,0xb3,0x08,0xb2,0xcb,0x79,0xf9,0x56,
     0xd8,0x58,0xd8,0xdf,0x49,0x77,0xc5,0x97,0x0f,0xe5,0xda,0xd2,0xc4,0x55,0x65,0xec,},
    {0x76,0x1f,0x75,0x68,0x4f,0x3c,0xdc,0x1b,0x64,0x37,0xbb,0x3a,0x01,0x44,0x5a,0xf1,
     0x51,0x1b,0x35,0x96,0x58,0x04,0x77,0xb8,0x3b,0x87,0x90,0x75,0xfa,0xed,0x07,0xe9,}
   },
   {{0x60,0x14,0x44,0x94,0xc8,0xf6,0x94,0x48,0x5b,0x85,0xec,0xb6,0xae,0xe1,0x09,0x56,
     0xc7,0x56,0x26,0x7d,0x12,0x89,0x47,0x11,0x92,0x22,0x43,0xd5,0xe8,0x55,0xb8,0xda,},
    {0x8b,0xb5,0xd6,0x69,0xf6,0x81,0xe6,0x46,0x9e,0x8b,0xe1,0xfd,0x91,0x32,0xe6,0x5b,
     0x54,0x39,0x55,0xc2,0x7e,0x3f,0x2a,0x4b,0xad,0x50,0x05,0x90,0xf3,0x4e,0x4b,0xbd,}
   },
   {{0x1e,0xc8,0x0f,0xef,0x36,0x0c,0xbd,0xd9,0x54,0x16,0x0f,0xad,0xab,0x35,0x2b,0x6b,
     0x92,0xb5,0x35,0x76,0xa8,0x8f,0xea,0x49,0x47,0x17,0x3b,0x9d,0x43,0x00,0xbf,0x19,},
    {0xae,0xef,0xe9,0x37,0x56,0xb5,0x34,0x0d,0x2f,0x3a,0x49,0x58,0xa7,0xab,0xbf,0x5e,
     0x01,0x46,0xe7,0x7f,0x62,0x95,0xa0,0x7b,0x67,0x1c,0xdc,0x1c,0xc1,0x07,0xce,0xfd,}
   },
   {{0x57,0x4e,0xf0,0xce,0x8a,0x59,0x7e,0x24,0xe5,0x67,0x0b,0x5c,0x0b,0xcd,0x14,0xcf,
     0xee,0xfc,0x98,0x3c,0x7e,0xcb,0x26,0x19,0x11,0xb2,0x36,0x55,0x79,0xde,0x5c,0xac,},
    {0x09,0xb9,0x99,0x30,0x28,0x1f,0x19,0xc7,0x3b,0xd6,0xad,0xa0,0x56,0x9b,0x78,0x45,
     0x1a,0x26,0x0a,0x7b,0xef,0x10,0x00,0x8c,0xae,0x59,0xae,0xa6,0xc7,0x5a,0x48,0x05,}
   },
   {{0x5a,0x3c,0xe2,0x5b,0x4d,0x15,0xb7,0xe2,0x2d,0x14,0x69,0xdd,0xf0,0xfc,0x9f,0x75,
     0xaf,0xd7,0xf1,0x2a,0xd3,0xcb,0xda,0x31,0xf8,0x14,0xba,0x1e,0xba,0xdb,0x2a,0x65,},
    {0x8b,0x34,0x12,0x5b,0x92,0xe0,0x5f,0x63,0x87,0x3a,0x6d,0xbf,0xbf,0x3f,0x99,0xaf,
     0x3e,0xe2,0x8b,0xc3,0xd8,0x25,0xfe,0x8e,0xd8,0xb1,0x70,0xcf,0x1d,0x32,0x7f,0x1d,}
   },
   {{0x71,0x75,0x40,0x7f,0x1b,0x58,0xf0,0x10,0xd4,0xcd,0xa4,0xc6,0x25,0x11,0xe5,0x9d,
     0xb7,0xed,0xcf,0x28,0xf5,0x47,0x6d,0x99,0x5c,0xf3,0x99,0x44,0xb2,0x6b,0x64,0xf1,},
    {0x43,0xb4,0x55,0x43,0x44,0xe3,0xd5,0x50,0xf3,0x6d,0x34,0x01,0x13,0x4c,0xc8,0x6e,
     0xb0,0x1f,0xe8,0xb7,0x74,0x47,0x1d,0x2a,0x42,0x6e,0x7e,0xfa,0xb2,0x42,0x34,0xd5,}
   },
   {{0x17,0x4a,0x53,0xb9,0xc9,0xa2,0x85,0x87,0x2d,0x39,0xe5,0x6e,0x69,0x13,0xca,0xb1,
     0x5d,0x59,0xb1,0xfa,0x51,0x25,0x08,0xc0,0x22,0xf3,0x82,0xde,0x83,0x19,0x49,0x7c,},
    {0xcc,0xc9,0xdc,0x37,0xab,0xfc,0x9c,0x16,0x57,0xb4,0x15,0x5f,0x2c,0x47,0xf9,0xe6,
     0x64,0x6b,0x3a,0x1d,0x8c,0xb9,0x85,0x43,0x83,0xda,0x13,0xac,0x07,0x9a,0xfa,0x73,}
   },
   {{0xcb,0xee,0x14,0x05,0xff,0x0d,0xa7,0xde,0xaf,0xe3,0x2c,0xa7,0xdd,0x73,0xd9,0x5e,
     0xd7,0x02,0x22,0x6b,0x39,0x17,0x47,0xc7,0x07,0x27,0x5a,0x94,0x0b,0xc8,0xf5,0x3b,},
    {0xf6,0x21,0x1f,0x4f,0x4e,0x75,0xf9,0x02,0xb5,0x1f,0x3e,0x68,0x9b,0x82,0x94,0xcf,
     0x0d,0x9f,0xf4,0xf6,0x81,0x26,0xf7,0x28,0x29,0x22,0xe6,0xb2,0x78,0xc8,0x7f,0x45,}
   },
   {{0xf7,0xae,0xf8,0xa7,0xe3,0x84,0x40,0x23,0x8f,0x93,0x32,0x90,0x6e,0x48,0xf6,0xfd,
     0x5a,0xdb,0xd0,0x2d,0x56,0xb7,0x6a,0x5f,0xfa,0x5a,0xca,0x58,0xc5,0x6c,0x39,0x43,},
    {0x4e,0x3b,0x0b,0x44,0xd5,0xff,0xda,0x79,0x7c,0x44,0x2b,0xbd,0xc3,0xab,0x3f,0xcf,
     0xee,0xc3,0x01,0x84,0xa8,0xdc,0xd0,0x03,0x43,0x1f,0x62,0x7f,0xac,0xf4,0x42,0xf1,}
   },
   {{0x71,0xc4,0xa7,0xe3,0x89,0xe2,0x96,0xce,0xd3,0x9d,0x75,0xef,0x5e,0x54,0x59,0x05,
     0xe5,0x00,0x50,0x64,0x0f,0x50,0xbe,0xcf,0x38,0xa6,0x0e,0xcb,0x23,0xb0,0x9d,0x0f,},
    {0x13,0x13,0xfa,0xdb,0x73,0x7a,0xf3,0xba,0x0a,0xf3,0xe0,0xa2,0x92,0xf8,0x10,0xaa,
     0x78,0x6f,0x2b,0x08,0x4a,0x62,0xff,0xc7,0x63,0x7b,0x1f,0x01,0x72,0x0d,0xdb,0x62,}
   },
   {{0x13,0x46,0x4a,0x57,0xa7,0x81,0x02,0xaa,0x62,0xb6,0x97,0x9a,0xe8,0x17,0xf4,0x63,
     0x7f,0xfc,0xfe,0xd3,0xc4,0xb1,0xce,0x30,0xbc,0xd6,0x30,0x3f,0x6c,0xaf,0x66,0x6b,},
    {0x69,0xbe,0x15,0x90,0x04,0x61,0x45,0x80,0xef,0x7e,0x43,0x34,0x53,0xcc,0xb0,0xca,
     0x48,0xf3,0x00,0xa8,0x1d,0x09,0x42,0xe1,0x3f,0x49,0x5a,0x90,0x7f,0x6e,0xcc,0x27,}
   },
   {{0xda,0x43,0x3d,0x5e,0x11,0xce,0xcc,0xc0,0xab,0xc5,0xc7,0x62,0x6c,0xe7,0xba,0xb4,
     0x2e,0x89,0xb2,0x21,0xf7,0x85,0xc4,0x09,0x28,0x2d,0xe5,0x45,0xf3,0xfc,0xeb,0x19,},
    {0xe4,0x98,0xdb,0xd3,0x21,0xa8,0x10,0x30,0x1d,0xeb,0xbd,0xc4,0xaf,0x95,0xe5,0x21,
     0x8e,0x77,0xfc,0x2d,0x92,0x27,0xb2,0x77,0x68,0x4e,0x71,0x20,0xa6,0xf5,0xcc,0x64,}
   },
   {{0x25,0x64,0xfe,0x9b,0x5b,0xee,0xf8,0x2d,0x37,0x03,0xa6,0x07,0x25,0x3f,0x31,0xef,
     0x8e,0xa1,0xb3,0x65,0x77,0x2d,0xf4,0x34,0x22,0x6a,0xee,0x64,0x26,0x51,0xb3,0xfa,},
    {0x8a,0xd9,0xf7,0xa6,0x06,0x78,0x38,0x90,0x95,0xfa,0x14,0xae,0x12,0x03,0x92,0x5f,
     0x14,0xf3,0x7d,0xab,0x6b,0x79,0x81,0x6e,0xdb,0x82,0xe6,0xa3,0x01,0xe5,0x12,0x2d,}
   },
   {{0xb2,0x37,0x90,0xa4,0x2b,0xe6,0x3e,0x1b,0x25,0x1a,0xd6,0xc9,0x4f,0xde,0xf0,0x72,
     0x71,0xec,0x0a,0xad,0xa3,0x1d,0xb6,0xc3,0xe8,0xbd,0x32,0x04,0x3f,0x8b,0xe3,0x84,},
    {0xfc,0x6b,0x69,0x49,0x19,0xd5,0x5e,0xdb,0xe8,0xd5,0x0f,0x88,0xaa,0x81,0xf9,0x45,
     0x17,0xf0,0x04,0xf4,0x14,0x9e,0xcb,0x58,0xd1,0x0a,0x47,0x3d,0xeb,0x19,0x88,0x0e,}
   },
};

static uint8_t p_data[PLEN] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xfc,0x2f,
};

static uint8_t n_data[PLEN] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41,
};


static int ecinit(ecpoint *a)
{
    int rslt;
    if ((rslt=mp_init_multi(&a->_x, &a->_y, NULL)) != MP_OKAY)
        return rslt;
    a->x = &a->_x;
    a->y = &a->_y;
    return MP_OKAY;
}

static void ecclear(ecpoint *a)
{
    mp_clear_multi(a->x, a->y, NULL);
}


static int ecdbl(ecpoint *a, mp_int *p, ecpoint *r)
{
    mp_int _xx, *xx=&_xx;
    mp_int _yy, *yy=&_yy;
    mp_int _rx, *rx=&_rx;
    int rslt;

    if (mp_iszero(a->x) && mp_iszero(a->y)) {
        mp_zero(r->x);
        mp_zero(r->y);
        return MP_OKAY;
    }

    if ((rslt=mp_init_multi(xx, yy, rx, NULL)) != MP_OKAY)
        return rslt;

    if ((rslt=mp_addmod(a->y, a->y, p, yy)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_invmod(yy, p, yy)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_sqrmod(a->x, p, xx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_addmod(xx, xx, p, rx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_addmod(rx, xx, p, xx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_mulmod(yy, xx, p, yy)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_sqrmod(yy, p, rx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_submod(rx, a->x, p, rx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_submod(rx, a->x, p, rx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_submod(a->x, rx, p, xx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_mulmod(xx, yy, p, yy)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_submod(yy, a->y, p, r->y)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_copy(rx, r->x)) != MP_OKAY)
        return rslt;

    mp_clear_multi(xx, yy, rx, NULL);
    return MP_OKAY;
}


static int ecadd(ecpoint *a, ecpoint *b, mp_int *p, ecpoint *r)
{
    mp_int _xx, *xx=&_xx;
    mp_int _yy, *yy=&_yy;
    mp_int _rx, *rx=&_rx;
    int rslt;

    if (mp_iszero(a->x) && mp_iszero(a->y)) {
        if ((rslt=mp_copy(b->x, r->x)) != MP_OKAY)
            return rslt;
        if ((rslt=mp_copy(b->y, r->y)) != MP_OKAY)
            return rslt;
        return MP_OKAY;
    }
    if (mp_iszero(b->x) && mp_iszero(b->y)) {
        if ((rslt=mp_copy(a->x, r->x)) != MP_OKAY)
            return rslt;
        if ((rslt=mp_copy(a->y, r->y)) != MP_OKAY)
            return rslt;
        return MP_OKAY;
    }

    if (mp_cmp(a->x, b->x) == MP_EQ) {
        if (mp_cmp(a->y, b->y) == MP_EQ) {
            return ecdbl(a, p, r);
        } else {
            mp_zero(r->x);
            mp_zero(r->y);
            return MP_OKAY;
        }
    }

    if ((rslt=mp_init_multi(xx, yy, rx, NULL)) != MP_OKAY)
        return rslt;

    if ((rslt=mp_submod(a->x, b->x, p, xx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_invmod(xx, p, xx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_submod(a->y, b->y, p, yy)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_mulmod(yy, xx, p, yy)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_sqrmod(yy, p, rx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_submod(rx, a->x, p, rx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_submod(rx, b->x, p, rx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_submod(a->x, rx, p, xx)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_mulmod(xx, yy, p, yy)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_submod(yy, a->y, p, r->y)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_copy(rx, r->x)) != MP_OKAY)
        return rslt;

    mp_clear_multi(xx, yy, rx, NULL);
    return MP_OKAY;
}


/* r = eG */
static int ecmul_g(mp_int *e, mp_int *p, ecpoint *r)
{
    ecpoint _g, *g=&_g;
    ecpoint _bb, *bb=&_bb;
    mp_int _ee, *ee=&_ee;
    int edig[NWINS];
    int i, j;
    int rslt;

    mp_init(ee);
    ecinit(g);
    ecinit(bb);

    /* split e into 5 bit pieces */
    if ((rslt=mp_copy(e, ee)) != MP_OKAY)
        return rslt;
    for (i=0; i<NWINS; i++) {
        edig[i] = WINMASK & mp_get_int(ee);
        if ((rslt=mp_div_2d(ee, 5, ee, NULL)) != MP_OKAY)
            return rslt;
    }

    mp_zero(r->x); mp_zero(r->y);
    ecinit(bb);

    for (j=WINMASK; j>=1; j--) {
        for (i=0; i<NWINS; i++) {
            if (edig[i] == j) {
                mp_read_unsigned_bin(g->x, G[i][0], PLEN);
                mp_read_unsigned_bin(g->y, G[i][1], PLEN);
                if ((rslt=ecadd(bb, g, p, bb)) != MP_OKAY)
                    return rslt;
            }
        }
        if ((rslt=ecadd(r, bb, p, r)) != MP_OKAY)
            return rslt;
    }

    mp_clear(ee);
    ecclear(g);
    ecclear(bb);
    memset(edig, 0, sizeof(edig));

    return MP_OKAY;
}


int sectopub(uint8_t *sec, uint8_t *pub)
{
    mp_int _p, *p=&_p;
    mp_int _s, *s=&_s;
    ecpoint _y, *y=&_y;
    int rslt;

    ecinit(y);
    mp_init_multi(p, s, 0);

    mp_read_unsigned_bin(p, p_data, PLEN);
    mp_read_unsigned_bin(s, sec, PLEN);
    if ((rslt=ecmul_g(s, p, y)) != MP_OKAY)
        return rslt;

    memset(pub, 0, 2*PLEN);
    mp_to_unsigned_bin(y->x, pub+(PLEN-mp_unsigned_bin_size(y->x)));
    mp_to_unsigned_bin(y->y, pub+PLEN+(PLEN-mp_unsigned_bin_size(y->y)));

    ecclear(y);
    mp_clear_multi(p, s, 0);
    return MP_OKAY;
}


int ecsign(uint8_t *rr, uint8_t *ss, uint8_t *hash, uint8_t *xx, uint8_t *kk)
{
    mp_int _p, *p=&_p;
    mp_int _n, *n=&_n;
    mp_int _h, *h=&_h;
    mp_int _x, *x=&_x;
    mp_int _k, *k=&_k;
    mp_int _s, *s=&_s;
    ecpoint _R, *R=&_R;
    int rslt;

    ecinit(R);
    mp_init_multi(p, n, h, x, k, s, 0);

    mp_read_unsigned_bin(p, p_data, PLEN);
    mp_read_unsigned_bin(n, n_data, PLEN);
    mp_read_unsigned_bin(h, hash, PLEN);
    mp_read_unsigned_bin(x, xx, PLEN);
    mp_read_unsigned_bin(k, kk, PLEN);

    if ((rslt=ecmul_g(k, p, R)) != MP_OKAY)
        return rslt;

    if ((rslt=mp_mulmod(R->x, x, n, s)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_addmod(s, h, n, s)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_invmod(k, n, k)) != MP_OKAY)
        return rslt;
    if ((rslt=mp_mulmod(s, k, n, s)) != MP_OKAY)
        return rslt;

    memset(rr, 0, PLEN);
    mp_to_unsigned_bin(R->x, rr+(PLEN-mp_unsigned_bin_size(R->x)));
    memset(ss, 0, PLEN);
    mp_to_unsigned_bin(s, ss+(PLEN-mp_unsigned_bin_size(s)));

    ecclear(R);
    mp_clear_multi(p, n, h, x, k, s, 0);
    return MP_OKAY;
}


int testmath(void)
{
    mp_int _p, *p=&_p;
    mp_int _e, *e=&_e;
    ecpoint _g, *g=&_g;
    ecpoint _gg, *gg=&_gg;
    ecpoint _gh, *gh=&_gh;

    ecinit(g);
    ecinit(gg);
    ecinit(gh);

    mp_init_multi(p, e, 0);
    mp_read_unsigned_bin(g->x, G[0][0], PLEN);
    mp_read_unsigned_bin(g->y, G[0][1], PLEN);
    mp_read_unsigned_bin(p, p_data, PLEN);
    record_timestamp("addmod start");
    mp_addmod(g->x, g->x, p, gg->x);
    record_timestamp("addmod end");
    record_timestamp("submod start");
    mp_submod(gg->x, g->x, p, gg->x);
    record_timestamp("submod end");
    record_timestamp("mulmod start");
    mp_mulmod(g->x, g->x, p, gg->x);
    record_timestamp("mulmod end");
    record_timestamp("invmod start");
    mp_invmod(g->x, p, gg->x);
    record_timestamp("invmod end");

    ecadd(g, g, p, gg);
    record_timestamp("ecadd start");
    ecadd(gg, g, p, gg);
    record_timestamp("ecadd end");

    record_timestamp("ecmul start");
    ecmul_g(gg->x, p, gg);
    record_timestamp("ecmul end");
    ecclear(g);
    ecclear(gg);
    ecclear(gh);

    mp_clear_multi(p, e, 0);
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
