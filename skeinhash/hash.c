//#include "crypto_hash.h"
#include <string.h>
#include "skein.h"
#include "sph_sha2.h"

typedef unsigned long u64;

int skeinhash
    (
    unsigned char *out,
    const unsigned char *in,
    unsigned long long inlen
    )

    {
	Skein_512_Ctxt_t ctx;
    sph_sha256_context mc;
    unsigned char hash1[64];

	Skein_512_Init  (&ctx,8*64);
	Skein_512_Update(&ctx,in,(size_t) inlen);
	Skein_512_Final (&ctx,hash1);

    sph_sha256_init(&mc);
    sph_sha256(&mc, hash1, 64);
    sph_sha256_close(&mc,out);

    return 0;
    }

int skeinhashmid
    (
    unsigned char *out,
    const unsigned char *in
    )

    {
    Skein_512_Ctxt_t ctx;

    Skein_512_Init  (&ctx,8*64);
    Skein_512_Update(&ctx,in,(size_t) 80);
    memcpy(out, ctx.X, 64);

    return 0;
    }
