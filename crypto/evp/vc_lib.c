/*
 * Copyright 2023 Fondazione Links.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.	
 *
 */

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


EVP_VC_CTX *EVP_VC_CTX_new(EVP_VC *vc) {

	EVP_VC_CTX *ctx = OPENSSL_zalloc(sizeof(EVP_VC_CTX));

	if (ctx == NULL
			|| (ctx->algctx = vc->newctx(ossl_provider_ctx(vc->prov))) == NULL
			|| !EVP_VC_up_ref(vc)) {
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
	EVP_VC_free(ctx->meth);
    OPENSSL_free(ctx);
}

char *EVP_VC_create(EVP_VC_CTX *ctx, EVP_PKEY *pkey, OSSL_PARAM params[]) {

	return ctx->meth->create(ctx->algctx, pkey, params);
}

int EVP_VC_verify(EVP_VC_CTX *ctx, EVP_PKEY *pkey, OSSL_PARAM params[]){

	return ctx->meth->verify(ctx->algctx, pkey, params);
}

int EVP_VC_deserialize(EVP_VC_CTX *ctx, char *vc_stream, OSSL_PARAM params[]) {

	return ctx->meth->deserialize(ctx->algctx, vc_stream, params);
}

char *EVP_VC_serialize(EVP_VC_CTX *ctx, OSSL_PARAM params[]) {

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

