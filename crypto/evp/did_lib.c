#include <string.h>
#include <stdarg.h>
#include <openssl/evp_ssi.h>
#include <openssl/err.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/types.h>
#include "internal/nelem.h"
#include "crypto/evp_ssi.h"
#include "internal/provider.h"
#include "evp_local_ssi.h"

EVP_DID_CTX *EVP_DID_CTX_new(EVP_DID *did){

	EVP_DID_CTX *ctx = OPENSSL_zalloc(sizeof(EVP_DID_CTX));

	if (ctx == NULL
			|| (ctx->algctx = did->newctx(ossl_provider_ctx(did->prov))) == NULL
			|| !EVP_DID_up_ref(did)) {
		ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
		if (ctx != NULL)
			did->freectx(ctx->algctx);
		OPENSSL_free(ctx);
		ctx = NULL;
	} else {
		ctx->meth = did;
	}
	return ctx;
}

void EVP_DID_CTX_free(EVP_DID_CTX *ctx){

	if (ctx == NULL)
		return;
	ctx->meth->freectx(ctx->algctx);
	ctx->algctx = NULL;
	/* EVP_DID_free(ctx->meth) */
	OPENSSL_free(ctx);
}

char *EVP_DID_create(EVP_DID_CTX *ctx, OSSL_PARAM params[]) {

	return ctx->meth->create(ctx->algctx, params);
}

int EVP_DID_resolve(EVP_DID_CTX *ctx, char *did, OSSL_PARAM params[]) {

	return ctx->meth->resolve(ctx->algctx, did, params);
}

int EVP_DID_update(EVP_DID_CTX *ctx, char *did, OSSL_PARAM params[]) {

	return ctx->meth->update(ctx->algctx, did, params);
}

int EVP_DID_revoke(EVP_DID_CTX *ctx, char *did) {

	return ctx->meth->revoke(ctx->algctx, did);
}

int EVP_DID_CTX_get_params(EVP_DID_CTX *ctx, OSSL_PARAM params[]){

	if (ctx->meth->get_ctx_params != NULL)
		return ctx->meth->get_ctx_params(ctx->algctx, params);
	return 1;
}

int EVP_DID_CTX_set_params(EVP_DID_CTX *ctx, OSSL_PARAM params[]) {

	if (ctx->meth->set_ctx_params != NULL)
			return ctx->meth->set_ctx_params(ctx->algctx, params);
	return 1;
}

