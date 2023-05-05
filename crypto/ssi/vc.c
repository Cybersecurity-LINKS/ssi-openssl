#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include "internal/provider.h"
#include <stdio.h>
#include <string.h>

#include <openssl/provider.h>
#include <openssl/ssi.h>
#include <crypto/ssi.h>

VC_CTX* VC_CTX_new(OSSL_PROVIDER *provider) {

	VC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

	    if (ctx == NULL ) {
	        printf("MALLOC ERROR\n");
	        OPENSSL_free(ctx);
	        //ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
	    }
	    ctx->prov = provider;
	    return ctx;
}

void VC_CTX_free(VC_CTX *ctx) {
    if (ctx == NULL)
        return;
    OPENSSL_free(ctx);
}

VC* VC_new(void) {

	return NULL;
}

void VC_free(VC* vc) {

	return;
}

int VC_fetch(OSSL_LIB_CTX *libctx, VC_CTX *ctx, const char *algorithm, const char *properties) {

	return 1;
}

int VC_create(VC_CTX *ctx, VC *vc) {

	return 1;
}

int VC_verify(VC_CTX *ctx, VC *vc) {

	return 1;
}

int VC_serialize(VC_CTX *ctx, unsigned char *vc_stream, VC *vc) {

	return 1;
}

int VC_deserialize(VC_CTX *ctx, unsigned char *vc_stream, VC *vc) {

	return 1;
}
