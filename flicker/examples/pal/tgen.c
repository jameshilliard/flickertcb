#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

main()
{
    EC_POINT *pt;
    EC_GROUP *group;
    BIGNUM *bnexp = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    unsigned char buf[65];
    int i, j;

    ENGINE_load_builtin_engines();
    CRYPTO_malloc_init();

    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    pt = EC_POINT_new(group);

    printf ("static unsigned char G32[52][2][32] = {\n");

    BN_one(bnexp);

    for (i=0; i<52; i++) {
        EC_POINT_mul(group, pt, bnexp, NULL, NULL, ctx);
        BN_lshift(bnexp, bnexp, 5);
        EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), ctx);
        printf("   {{");
        for (j=1; j<33; j++)
            printf("0x%02x,%s", buf[j], (j==16)?"\n     ":"");
        printf("},\n    {");
        for (; j<65; j++)
            printf("0x%02x,%s", buf[j], (j==48)?"\n     ":"");
        printf("}\n   },\n");
    }
    printf("};\n");
}
