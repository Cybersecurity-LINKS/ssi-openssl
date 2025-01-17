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

#include <openssl/evp_ssi.h>
#include <openssl/types.h>
#include <openssl/ssl.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <crypto/vc.h>
#include <ssl/ssl_local.h>
#include <stdio.h>
#include <stdlib.h>

int SSL_CTX_set_vc(SSL_CTX *ctx, char *vc_file) {

	EVP_VC_CTX *evp_ctx = NULL;
	EVP_VC *evp_vc = NULL;
	OSSL_PARAM params[13];
	size_t params_n = 0;

	FILE *vc_fp = NULL;

	size_t n = 0;
	int c;
	char *vc_stream;

	VC *tmp = OPENSSL_zalloc(sizeof(*tmp));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

	vc_fp = fopen(vc_file, "r");
	if (vc_fp == NULL)
		return 0;

	fseek(vc_fp, 0, SEEK_END);
	long f_size = ftell(vc_fp);
	fseek(vc_fp, 0, SEEK_SET);
	vc_stream = malloc(f_size);

	while ((c = fgetc(vc_fp)) != EOF) {
		vc_stream[n++] = (unsigned char)c;
	}

	evp_vc = EVP_VC_fetch(NULL, "DM2", NULL);
	if (evp_vc == NULL)
		goto err;

	/* Create a context for the vc operation */
	evp_ctx = EVP_VC_CTX_new(evp_vc);
	if (evp_ctx == NULL)
		goto err;

	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_CONTEXT, &tmp->atContext, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_ID, &tmp->id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_TYPE, &tmp->type, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_ISSUER, &tmp->issuer, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_ISSUANCE_DATE, &tmp->issuanceDate, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_EXPIRATION_DATE, &tmp->expirationDate, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_SUBJECT, &tmp->credentialSubject, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_PROOF_TYPE, &tmp->proofType, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_PROOF_CREATED, &tmp->proofCreated, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_PROOF_PURPOSE, &tmp->proofPurpose, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_VERIFICATION_METHOD, &tmp->verificationMethod, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_PROOF_VALUE, &tmp->proofValue, 0);
	params[params_n] = OSSL_PARAM_construct_end();

	if(!EVP_VC_deserialize(evp_ctx, vc_stream, params))
		goto err;

	ctx->vc->atContext = OPENSSL_strdup(tmp->atContext);
	ctx->vc->id = OPENSSL_strdup(tmp->id);
	ctx->vc->type = OPENSSL_strdup(tmp->type);
	ctx->vc->issuer = OPENSSL_strdup(tmp->issuer);
	ctx->vc->issuanceDate = OPENSSL_strdup(tmp->issuanceDate);
	ctx->vc->expirationDate = OPENSSL_strdup(tmp->expirationDate);
	ctx->vc->credentialSubject = OPENSSL_strdup(tmp->credentialSubject);
	ctx->vc->proofType = OPENSSL_strdup(tmp->proofType);
	ctx->vc->proofCreated = OPENSSL_strdup(tmp->proofCreated);
	ctx->vc->proofPurpose = OPENSSL_strdup(tmp->proofPurpose);
	ctx->vc->verificationMethod = OPENSSL_strdup(tmp->verificationMethod);
	ctx->vc->proofValue = OPENSSL_strdup(tmp->proofValue);

	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(evp_ctx);
	OPENSSL_free(tmp);

	return 1;

err:

	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(evp_ctx);
	OPENSSL_free(tmp);

	return 0;
}

int SSL_CTX_set_vc_issuers(SSL_CTX *ctx, char* vc_issuers_file) {

	size_t n = 0;
	unsigned char *pubkey;
	BIO *key;
	char c;

	FILE *vc_issuers_fp = fopen(vc_issuers_file, "r");
	if (vc_issuers_fp == NULL)
		return 0;

	ctx->trusted_issuers = (VC_ISSUER*) malloc(sizeof(VC_ISSUER));
	if(ctx->trusted_issuers == NULL) {
		ERR_raise(ERR_LIB_SSL, ERR_R_INIT_FAIL);
		return 0;
	}

	ctx->trusted_issuers->verificationMethod = OPENSSL_zalloc(100);
	while((c = fgetc(vc_issuers_fp)) != '\n'){
		ctx->trusted_issuers->verificationMethod[n++] = c;
	}
	fseek(vc_issuers_fp, 0, SEEK_END);
	long f_size = ftell(vc_issuers_fp) - strlen(ctx->trusted_issuers->verificationMethod);
	fseek(vc_issuers_fp, strlen(ctx->trusted_issuers->verificationMethod), SEEK_SET);
	pubkey = malloc(f_size + 1);


	for (n = 0; n < f_size; n++) {
		pubkey[n] = fgetc(vc_issuers_fp);
	}
	pubkey[f_size] = '\0';

	if ((key = BIO_new_mem_buf(pubkey, -1)) == NULL) {
		return 0;
	}

	if ((ctx->trusted_issuers->pubkey = PEM_read_bio_PUBKEY(key, NULL, NULL,
			NULL)) == NULL) {
		return 0;
	}

	ctx->trusted_issuers_num = 1;
	
	ctx->ext.ssi_params.ssiauth = VC_AUTHN;

	return 1;
}

VC *ssl_vc_new(void) {

	VC *ret = OPENSSL_zalloc(sizeof(*ret));

	if(ret == NULL) {
		ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	return ret;
}

VC* ssl_vc_dup(VC *vc) {

	VC *ret = OPENSSL_zalloc(sizeof(*ret));

	if (ret == NULL) {
		ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (vc->atContext != NULL)
		ret->atContext = OPENSSL_strdup(vc->atContext);
	if (vc->id != NULL)
		ret->id = OPENSSL_strdup(vc->id);
	if (vc->type != NULL)
		ret->type = OPENSSL_strdup(vc->type);
	if (vc->issuer != NULL)
		ret->issuer = OPENSSL_strdup(vc->issuer);
	if (vc->issuanceDate != NULL)
		ret->issuanceDate = OPENSSL_strdup(vc->issuanceDate);
	if (vc->expirationDate != NULL)
		ret->expirationDate = OPENSSL_strdup(vc->expirationDate);
	if (vc->credentialSubject != NULL)
		ret->credentialSubject = OPENSSL_strdup(vc->credentialSubject);
	if (vc->proofType != NULL)
		ret->proofType = OPENSSL_strdup(vc->proofType);
	if (vc->proofCreated != NULL)
		ret->proofCreated = OPENSSL_strdup(vc->proofCreated);
	if (vc->proofPurpose != NULL)
		ret->proofPurpose = OPENSSL_strdup(vc->proofPurpose);
	if (vc->verificationMethod != NULL)
		ret->verificationMethod = OPENSSL_strdup(vc->verificationMethod);
	if (vc->proofValue != NULL)
		ret->proofValue = OPENSSL_strdup(vc->proofValue);

	return ret;
}


VC_ISSUER* ssl_vc_issuers_dup(VC_ISSUER *issuers, size_t issuers_num) {

	VC_ISSUER *ret = OPENSSL_zalloc(issuers_num * sizeof(VC_ISSUER));

	if (ret == NULL) {
		ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	ret->pubkey = issuers->pubkey;
	ret->verificationMethod = issuers->verificationMethod;

	return ret;
}

/*
 * Should we send an SSIRequest message?
 *
 * Valid return values are:
 *   1: Yes
 *   0: No
 */

int send_ssi_request(SSL *s) {
	if (
	/* don't request did unless asked for it: */
	s->verify_mode & SSL_VERIFY_PEER && 
	(s->ext.ssi_params.ssiauth == DID_AUTHN || s->ext.ssi_params.ssiauth == VC_AUTHN) && 
	s->ext.ssi_params.didmethods != NULL 
//			/*
//			 * don't request if post-handshake-only unless doing
//			 * post-handshake in TLSv1.3:
//			 */
//			&& (!SSL_IS_TLS13(s)
//					|| !(s->verify_mode & SSL_VERIFY_POST_HANDSHAKE)
//					|| s->post_handshake_auth == SSL_PHA_REQUEST_PENDING)
//			/*
//			 * if SSL_VERIFY_CLIENT_ONCE is set, don't request cert
//			 * a second time:
//			 */
//			&& (s->certreqs_sent < 1
//					|| !(s->verify_mode & SSL_VERIFY_CLIENT_ONCE))
//			/*
//			 * never request cert in anonymous ciphersuites (see
//			 * section "Certificate request" in SSL 3 drafts and in
//			 * RFC 2246):
//			 */
//			&& (!(s->s3.tmp.new_cipher->algorithm_auth & SSL_aNULL)
//			/*
//			 * ... except when the application insists on
//			 * verification (against the specs, but statem_clnt.c accepts
//			 * this for SSL 3)
//			 */
//			|| (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT))
//			/* don't request certificate for SRP auth */
//			&& !(s->s3.tmp.new_cipher->algorithm_auth & SSL_aSRP)
//			/*
//			 * With normal PSK Did and Did Requests
//			 * are omitted
//			 */
//			&& !(s->s3.tmp.new_cipher->algorithm_auth & SSL_aPSK)
					) {
		return 1;
	}

	return 0;
}

/* Declared in openssl/include/openssl/ssl.h */
char *SSL_get0_peer_vc(const SSL *s){

	if ((s == NULL) || (s->session == NULL))
	        return NULL;
	    else
	        return s->session->peer_vc_stream;
}

int is_vc_handshake(const SSL *s){

	if(s == NULL || !SSL_IS_TLS13(s))
		return 0;

	return s->s3.ssi_params_sent && s->session->peer_vc_stream;
}

