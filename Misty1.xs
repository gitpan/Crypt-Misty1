#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"
#include "_misty1.c"

typedef struct misty1 {
    unsigned char *key;
    unsigned char *buf;
}* Crypt__Misty1;

MODULE = Crypt::Misty1		PACKAGE = Crypt::Misty1		
PROTOTYPES: DISABLE

int
keysize(...)
    CODE:
        RETVAL = 16;
    OUTPUT:
        RETVAL

int
blocksize(...)
    CODE:
        RETVAL = 8;
    OUTPUT:
        RETVAL

Crypt::Misty1
new(class, rawkey)
    SV* class
    SV* rawkey
    CODE:
    {
        STRLEN keyLength;
        if (! SvPOK(rawkey))
            croak("Error initialization: key must be a NUL-terminated string!");

        keyLength = SvCUR(rawkey);
        if (keyLength != 16)
            croak("Error initialization: key must be 16 bytes in length!");

        Newz(0, RETVAL, 1, struct misty1);
        RETVAL->key = SvPV_nolen(rawkey);
    }

    OUTPUT:
        RETVAL

void
DESTROY(self)
    Crypt::Misty1 self
    CODE:
        Safefree(self);

SV*
encrypt(self, input)
    Crypt::Misty1 self
    SV* input
    CODE:
    {
        STRLEN blockSize;
        unsigned char *rawbytes;
        rawbytes = SvPV(input, blockSize);
        if (blockSize != 8) {
            croak("Error encryption: block size must be 8 bytes in length!");
            RETVAL = newSVpv("", 0);
        } else {
            RETVAL = NEWSV(0, 8);
            SvPOK_only(RETVAL);
            SvCUR_set(RETVAL, 8);
            misty1(rawbytes, self->key, 1, 0);
        }
    }

    OUTPUT:
        RETVAL

