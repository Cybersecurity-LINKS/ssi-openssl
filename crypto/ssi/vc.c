#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include "internal/provider.h"
#include <stdio.h>
#include <string.h>

#include <openssl/provider.h>
#include <openssl/ssi.h>
#include <crypto/ssi.h>

SSI_VC_CTX *SSI_VC_CTX_new(SSI_VC *vc) {

	SSI_VC_CTX *ctx = OPENSSL_zalloc(sizeof(SSI_VC_CTX));

	if (ctx == NULL
			|| (ctx->algctx = vc->newctx(ossl_provider_ctx(vc->prov))) == NULL
			/* || SSI_VC_up_ref(vc) */) {
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

void SSI_VC_CTX_free(SSI_VC_CTX *ctx) {

	if (ctx == NULL)
        return;
	ctx->meth->freectx(ctx->algctx);
	ctx->algctx = NULL;
	/* SSI_VC_free(ctx->meth) */
    OPENSSL_free(ctx);
}

SSI_VC *SSI_VC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm, const char *properties) {

	return NULL;
}

char *SSI_VC_create(SSI_VC_CTX *ctx, EVP_PKEY *pkey, OSSL_PARAM params[]) {

	return ctx->meth->create(ctx->algctx, pkey, params);
}

int SSI_VC_verify(SSI_VC_CTX *ctx, EVP_PKEY *pkey, OSSL_PARAM params[]){

	return ctx->meth->verify(ctx->algctx, pkey, params);
}

int SSI_VC_deserialize(SSI_VC_CTX *ctx, unsigned char *vc_stream, OSSL_PARAM params[]) {

	return ctx->meth->deserialize(ctx->algctx, vc_stream, params);
}


unsigned char *SSI_VC_serialize(SSI_VC_CTX *ctx, OSSL_PARAM params[]) {

	return ctx->meth->serialize(ctx->algctx, params);
}

int SSI_VC_CTX_get_params(SSI_VC_CTX *ctx, OSSL_PARAM params[]){

	if (ctx->meth->get_ctx_params != NULL)
	        return ctx->meth->get_ctx_params(ctx->algctx, params);
	    return 1;
}

int SSI_VC_CTX_set_params(SSI_VC_CTX *ctx, OSSL_PARAM params[]){

	if (ctx->meth->set_ctx_params != NULL)
	        return ctx->meth->set_ctx_params(ctx->algctx, params);
	    return 1;
}


