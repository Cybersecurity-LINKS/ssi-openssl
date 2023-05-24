#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include "internal/provider.h"
#include <stdio.h>
#include <string.h>
#include <openssl/types.h>

#include <openssl/provider.h>
#include "../../include/crypto/evp_ssi.h"
#include "../../include/openssl/evp_ssi.h"

EVP_VC_CTX *EVP_VC_CTX_new(EVP_VC *vc) {

	EVP_VC_CTX *ctx = OPENSSL_zalloc(sizeof(EVP_VC_CTX));

	if (ctx == NULL
			|| (ctx->algctx = vc->newctx(ossl_provider_ctx(vc->prov))) == NULL
			/* || EVP_VC_up_ref(vc) */) {
		ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
		if(ctx != NULL)
			vc->freectx(ctx->algctx);
		OPENSSL_free(ctx);
		ctx = NULL;
	} else {
		ctx->meth = vc;
	}
	return ctx;
}

void EVP_VC_CTX_free(EVP_VC_CTX *ctx) {

	if (ctx == NULL)
        return;
	ctx->meth->freectx(ctx->algctx);
	ctx->algctx = NULL;
	/* EVP_VC_free(ctx->meth) */
    OPENSSL_free(ctx);
}

EVP_VC *EVP_VC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm, const char *properties) {

	return NULL;
}

void EVP_VC_CTX_free(EVP_VC_CTX *ctx) {
    if (ctx == NULL)
        return;
    OPENSSL_free(ctx);
}

char *EVP_VC_create(EVP_VC_CTX *ctx, EVP_PKEY *pkey, OSSL_PARAM params[]) {

	return ctx->meth->create(ctx->algctx, pkey, params);
}

int EVP_VC_verify(EVP_VC_CTX *ctx, EVP_PKEY *pkey, OSSL_PARAM params[]){

	return ctx->meth->verify(ctx->algctx, pkey, params);
}

int EVP_VC_deserialize(EVP_VC_CTX *ctx, unsigned char *vc_stream, OSSL_PARAM params[]) {

	return ctx->meth->deserialize(ctx->algctx, vc_stream, params);
}


unsigned char *EVP_VC_serialize(EVP_VC_CTX *ctx, OSSL_PARAM params[]) {

	return ctx->meth->serialize(ctx->algctx, params);
}

int EVP_VC_CTX_get_params(EVP_VC_CTX *ctx, OSSL_PARAM params[]){

	if (ctx->meth->get_ctx_params != NULL)
	        return ctx->meth->get_ctx_params(ctx->algctx, params);
	    return 1;
}

int EVP_VC_CTX_set_params(EVP_VC_CTX *ctx, OSSL_PARAM params[]){

	if (ctx->meth->set_ctx_params != NULL)
	        return ctx->meth->set_ctx_params(ctx->algctx, params);
	    return 1;
}
