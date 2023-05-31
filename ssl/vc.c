/*
 * vc.c
 *
 *  Created on: May 31, 2023
 *      Author: pirug
 */

#include <openssl/evp_ssi.h>
#include <openssl/types.h>

int SSL_CTX_set_vc(SSL_CTX *ctx, unsigned char *vc_stream) {

	EVP_VC_CTX *evp_ctx = NULL;
	EVP_VC *evp_vc = NULL;
	OSSL_PARAMS params[13];
	size_t params_n = 0;

	OSSL_PROVIDER *provider = NULL;

	ctx->vc = (VC*)OPENSSL_malloc(sizeof(VC));

	provider = OSSL_provider_load(NULL, "ssiprovider");
	if (provider == NULL) {
		printf("SSI provider load failed\n");
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return MSG_PROCESS_ERROR;
	}

	evp_vc = EVP_VC_fetch(NULL, "vc", NULL);
	if (evp_vc == NULL)
		goto err;

	/* Create a context for the vc operation */
	evp_ctx = EVP_VC_CTX_new(evp_vc);
	if (ctx == NULL)
		goto err;

	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_CONTEXT, ctx->vc->atContext, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ID, ctx->vc->id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_TYPE, ctx->vc->type, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUER, ctx->vc->issuer, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUANCE_DATE, ctx->vc->issuanceDate, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_EXPIRATION_DATE, ctx->vc->issuanceDate, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_SUBJECT, ctx->vc->credentialSubject, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_TYPE, ctx->vc->proofType, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_CREATED, ctx->vc->proofCreated, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_PURPOSE, ctx->vc->proofPurpose, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_VERIFICATION_METHOD, ctx->vc->verificationMethod, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_VALUE, ctx->vc->proofValue, 0);
	params[params_n] = OSSL_PARAM_construct_end();

	if(!EVP_VC_deserialize(evp_ctx, vc_stream, params))
		goto err;

	OSSL_PROVIDER_unload(provider);
	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(evp_ctx);

	return 1;

err:
	OSSL_PROVIDER_unload(provider);
	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(evp_ctx);

	return 0;
}
