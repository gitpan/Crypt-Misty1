/****************************************************
*
* MISTY1 Block Cipher Algorithm (8-round/ECB) *
*
* Language : Highly Portable C Language *
* Coding by : Mitsuru Matsui / 22 July 1996 *
* Copyright : Mitsubishi Electric Coporation *
*
* Slight modifications by Julius C. Duque <jcduque (AT) lycos (DOT) com>
* 2003 May 28th
*
****************************************************/

#include <stdio.h>

unsigned short EXTKEY[4][8];

static unsigned char S7[128] = {
27,  50,  51,  90,  59,  16,  23,  84,  91,  26, 114, 115, 107,  44, 102,  73,
31,  36,  19, 108,  55,  46,  63,  74,  93,  15,  64,  86,  37,  81,  28,   4,
11,  70,  32,  13, 123,  53,  68,  66,  43,  30,  65,  20,  75, 121,  21, 111,
14,  85,   9,  54, 116,  12, 103,  83,  40,  10, 126,  56,   2,   7,  96,  41,
25,  18, 101,  47,  48,  57,   8, 104,  95, 120,  42,  76, 100,  69, 117,  61,
89,  72,   3,  87, 124,  79,  98,  60,  29,  33,  94,  39, 106, 112,  77,  58,
 1, 109, 110,  99,  24, 119,  35,   5,  38, 118,   0,  49,  45, 122, 127,  97,
80,  34,  17,  6,   71,  22,  82,  78, 113,  62, 105,  67,  52,  92,  88, 125
};

static unsigned short S9[512] = {
451, 203, 339, 415, 483, 233, 251,  53, 385, 185, 279, 491, 307,   9,  45, 211,
199, 330,  55, 126, 235, 356, 403, 472, 163, 286,  85,  44,  29, 418, 355, 280,
331, 338, 466,  15,  43,  48, 314, 229, 273, 312, 398,  99, 227, 200, 500,  27,
  1, 157, 248, 416, 365, 499,  28, 326, 125, 209, 130, 490, 387, 301, 244, 414,
467, 221, 482, 296, 480, 236,  89, 145,  17, 303,  38, 220, 176, 396, 271, 503,
231, 364, 182, 249, 216, 337, 257, 332, 259, 184, 340, 299, 430,  23, 113,  12,
 71,  88, 127, 420, 308, 297, 132, 349, 413, 434, 419,  72, 124,  81, 458,  35,
317, 423, 357,  59,  66, 218, 402, 206, 193, 107, 159, 497, 300, 388, 250, 406,
481, 361, 381,  49, 384, 266, 148, 474, 390, 318, 284,  96, 373, 463, 103, 281,
101, 104, 153, 336,   8,   7, 380, 183,  36,  25, 222, 295, 219, 228, 425,  82,
265, 144, 412, 449,  40, 435, 309, 362, 374, 223, 485, 392, 197, 366, 478, 433,
195, 479,  54, 238, 494, 240, 147,  73, 154, 438, 105, 129, 293,  11,  94, 180,
329, 455, 372,  62, 315, 439, 142, 454, 174,  16, 149, 495,  78, 242, 509, 133,
253, 246, 160, 367, 131, 138, 342, 155, 316, 263, 359, 152, 464, 489,   3, 510,
189, 290, 137, 210, 399,  18,  51, 106, 322, 237, 368, 283, 226, 335, 344, 305,
327,  93, 275, 461, 121, 353, 421, 377, 158, 436, 204,  34, 306,  26, 232,   4,
391, 493, 407,  57, 447, 471,  39, 395, 198, 156, 208, 334, 108,  52, 498, 110,
202,  37, 186, 401, 254,  19, 262,  47, 429, 370, 475, 192, 267, 470, 245, 492,
269, 118, 276, 427, 117, 268, 484, 345,  84, 287,  75, 196, 446, 247,  41, 164,
 14, 496, 119,  77, 378, 134, 139, 179, 369, 191, 270, 260, 151, 347, 352, 360,
215, 187, 102, 462, 252, 146, 453, 111,  22,  74, 161, 313, 175, 241, 400,  10,
426, 323, 379,  86, 397, 358, 212, 507, 333, 404, 410, 135, 504, 291, 167, 440,
321,  60, 505, 320,  42, 341, 282, 417, 408, 213, 294, 431,  97, 302, 343, 476,
114, 394, 170, 150, 277, 239,  69, 123, 141, 325,  83,  95, 376, 178,  46,  32,
469,  63, 457, 487, 428,  68,  56,  20, 177, 363, 171, 181,  90, 386, 456, 468,
 24, 375, 100, 207, 109, 256, 409, 304, 346,   5, 288, 443, 445, 224,  79, 214,
319, 452, 298,  21,   6, 255, 411, 166,  67, 136,  80, 351, 488, 289, 115, 382,
188, 194, 201, 371, 393, 501, 116, 460, 486, 424, 405,  31,  65,  13, 442,  50,
 61, 465, 128, 168,  87, 441, 354, 328, 217, 261,  98, 122,  33, 511, 274, 264,
448, 169, 285, 432, 422, 205, 243,  92, 258,  91, 473, 324, 502, 173, 165,  58,
459, 310, 383,  70, 225,  30, 477, 230, 311, 506, 389, 140, 143,  64, 437, 190,
120,   0, 172, 272, 350, 292,   2, 444, 162, 234, 112, 508, 278, 348,  76, 450
};

#define FL_enc(k) {\
r1 ^= r0 & EXTKEY[0][k];\
r3 ^= r2 & EXTKEY[1][(k+2)&7];\
r0 ^= r1 | EXTKEY[1][(k+6)&7];\
r2 ^= r3 | EXTKEY[0][(k+4)&7];\
}

#define FL_dec(k) {\
r0 ^= r1 | EXTKEY[0][(k+4)&7];\
r2 ^= r3 | EXTKEY[1][(k+6)&7];\
r1 ^= r0 & EXTKEY[1][(k+2)&7];\
r3 ^= r2 & EXTKEY[0][k];\
}

#define FI_key(k) {\
r0 = EXTKEY[0][k] >> 7;\
r1 = EXTKEY[0][k] & 0x7f;\
r0 = S9[r0] ^ r1;\
r1 = S7[r1] ^ (r0 & 0x7f);\
r1 ^= EXTKEY[0][(k+1)&7] >> 9;\
r0 ^= EXTKEY[0][(k+1)&7] & 0x1ff;\
r0 = S9[r0] ^ r1;\
EXTKEY[3][k] = r1;\
EXTKEY[2][k] = r0;\
EXTKEY[1][k] = r1 << 9 ^ r0;\
}

#define FI_txt(a0, a1, k) {\
a1 = a0 >> 7;\
a0 &= 0x7f;\
a1 = S9[a1] ^ a0;\
a0 = S7[a0] ^ a1;\
a1 ^= EXTKEY[2][k];\
a0 ^= EXTKEY[3][k];\
a0 &= 0x7f;\
a1 = S9[a1] ^ a0;\
a1 ^= a0 << 9;\
}

#define FO_txt(a0, a1, a2, a3, k) {\
t0 = a0 ^ EXTKEY[0][k];\
FI_txt(t0, t1, (k+5)&7);\
t1 ^= a1;\
t2 = a1 ^ EXTKEY[0][(k+2)&7];\
FI_txt(t2, t0, (k+1)&7);\
t0 ^= t1;\
t1 ^= EXTKEY[0][(k+7)&7];\
FI_txt(t1, t2, (k+3)&7);\
t2 ^= t0;\
t0 ^= EXTKEY[0][(k+4)&7];\
a2 ^= t0;\
a3 ^= t2;\
}

/***********************************************
*
* Encryption/Decryption Subroutine Body
*
* misty1(text, key, block, mode)
*
* text  : plain/ciphertext address I/O
* key   : secret-key address
* block : number of text blocks
* mode  : 0: encryption 1: decryption
*
***********************************************/

void misty1(unsigned char *text, unsigned char *key,
    int block, int mode)
{
  register unsigned short t0, t1, t2;
  register unsigned short r0, r1, r2, r3;

  /*** Key Scheduling ***/
  EXTKEY[0][0] = (unsigned short)key[0]<<8 ^ (unsigned short)key[1];
  EXTKEY[0][1] = (unsigned short)key[2]<<8 ^ (unsigned short)key[3];
  EXTKEY[0][2] = (unsigned short)key[4]<<8 ^ (unsigned short)key[5];
  EXTKEY[0][3] = (unsigned short)key[6]<<8 ^ (unsigned short)key[7];
  EXTKEY[0][4] = (unsigned short)key[8]<<8 ^ (unsigned short)key[9];
  EXTKEY[0][5] = (unsigned short)key[10]<<8 ^ (unsigned short)key[11];
  EXTKEY[0][6] = (unsigned short)key[12]<<8 ^ (unsigned short)key[13];
  EXTKEY[0][7] = (unsigned short)key[14]<<8 ^ (unsigned short)key[15];
  FI_key(0);
  FI_key(1);
  FI_key(2);
  FI_key(3);
  FI_key(4);
  FI_key(5);
  FI_key(6);
  FI_key(7);

  /*** Data Randomizing ***/
  if(!(mode & 1)) {
    /*** Encryption ***/
    while(block-- > 0) {
      r0 = (unsigned short)text[0]<<8 ^ (unsigned short)text[1];
      r1 = (unsigned short)text[2]<<8 ^ (unsigned short)text[3];
      r2 = (unsigned short)text[4]<<8 ^ (unsigned short)text[5];
      r3 = (unsigned short)text[6]<<8 ^ (unsigned short)text[7];
      FL_enc(0);
      FO_txt(r0, r1, r2, r3, 0);
      FO_txt(r2, r3, r0, r1, 1);
      FL_enc(1);
      FO_txt(r0, r1, r2, r3, 2);
      FO_txt(r2, r3, r0, r1, 3);
      FL_enc(2);

      FO_txt(r0, r1, r2, r3, 4);
      FO_txt(r2, r3, r0, r1, 5);
      FL_enc(3);
      FO_txt(r0, r1, r2, r3, 6);
      FO_txt(r2, r3, r0, r1, 7);
      FL_enc(4);

      text[0] = r2 >> 8;
      text[1] = r2 & 0xff;
      text[2] = r3 >> 8;
      text[3] = r3 & 0xff;
      text[4] = r0 >> 8;
      text[5] = r0 & 0xff;
      text[6] = r1 >> 8;
      text[7] = r1 & 0xff;
      text += 8;
    }
  } else {
    /*** Decryption ***/
    while(block-- > 0) {
      r0 = (unsigned short)text[0]<<8 ^ (unsigned short)text[1];
      r1 = (unsigned short)text[2]<<8 ^ (unsigned short)text[3];
      r2 = (unsigned short)text[4]<<8 ^ (unsigned short)text[5];
      r3 = (unsigned short)text[6]<<8 ^ (unsigned short)text[7];

      FL_dec(4);
      FO_txt(r0, r1, r2, r3, 7);
      FO_txt(r2, r3, r0, r1, 6);
      FL_dec(3);
      FO_txt(r0, r1, r2, r3, 5);
      FO_txt(r2, r3, r0, r1, 4);
      FL_dec(2);
      FO_txt(r0, r1, r2, r3, 3);
      FO_txt(r2, r3, r0, r1, 2);
      FL_dec(1);
      FO_txt(r0, r1, r2, r3, 1);
      FO_txt(r2, r3, r0, r1, 0);
      FL_dec(0);

      text[0] = r2 >> 8;
      text[1] = r2 & 0xff;
      text[2] = r3 >> 8;
      text[3] = r3 & 0xff;
      text[4] = r0 >> 8;
      text[5] = r0 & 0xff;
      text[6] = r1 >> 8;
      text[7] = r1 & 0xff;
      text += 8;
    }
  }
}

int main(void)
{
  static unsigned char text[16] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
  };

  static unsigned char key[16] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
  };

  int i;

  printf("Secret Key          : ");
  for(i = 0; i < 16; i++) printf("%02x ", key[i]);
  printf("\n");

  printf("Orig Plaintext      : ");
  for(i = 0; i < 16; i++) printf("%02x ", text[i]);
  printf("\n");

  misty1(text, key, 2, 0);
  printf("Extended Key        : ");
  for(i = 0; i < 8; i++)
    printf("%02x %02x ", (unsigned char)(EXTKEY[1][i]>>8),
        (unsigned char)(EXTKEY[1][i]&0xff));
  printf("\n");

  printf("Ciphertext          : ");
  for(i = 0; i < 16; i++) printf("%02x ", text[i]);
  printf("\n");

  misty1(text, key, 2, 1);
  printf("Decrypted Plaintext : ");
  for(i = 0; i < 16; i++) printf("%02x ", text[i]);
  printf("\n");

  return 0;
}

