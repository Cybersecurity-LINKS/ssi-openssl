/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/tls1.h>
#include <ssl/ssl_local_did.h>

#include "statem_local_ssi.h"
#include <openssl/provider.h>
#include <openssl/evp_ssi.h>
#include <openssl/core_names.h>

int init_ssi_params(SSL *s, unsigned int context)
{
	s->ext.peer_ssi_params.ssiauth = 0;
	/* Clear any supported did method received */
	OPENSSL_free(s->ext.peer_ssi_params.didmethods);
	s->ext.peer_ssi_params.didmethods = NULL;
	s->ext.peer_ssi_params.didmethods_len = 0;

	return 1;
}

/*
 * Size of the to-be-signed TLS13 data, without the hash size itself:
 * 64 bytes of value 32, 33 context bytes, 1 byte separator
 */
#define TLS13_DID_TBS_START_SIZE 64
#define TLS13_DID_TBS_PREAMBLE_SIZE (TLS13_DID_TBS_START_SIZE + 25 + 1)

static int get_did_verify_tbs_data(SSL *s, unsigned char *tls13tbs,
								   void **hdata, size_t *hdatalen)
{
	static const char servercontext[] = "TLS 1.3, server DidVerify";
	static const char clientcontext[] = "TLS 1.3, client DidVerify";

	if (SSL_IS_TLS13(s))
	{
		size_t hashlen;

		/* Set the first 64 bytes of to-be-signed data to octet 32 */
		memset(tls13tbs, 32, TLS13_DID_TBS_START_SIZE);
		/* This copies the 33 bytes of context plus the 0 separator byte */
		if (s->statem.hand_state == TLS_ST_CR_DID_VRFY || s->statem.hand_state == TLS_ST_SW_DID_VRFY)
			strcpy((char *)tls13tbs + TLS13_DID_TBS_START_SIZE, servercontext);
		else
			strcpy((char *)tls13tbs + TLS13_DID_TBS_START_SIZE, clientcontext);

		/*
		 * If we're currently reading then we need to use the saved handshake
		 * hash value. We can't use the current handshake hash state because
		 * that includes the CertVerify itself.
		 */
		if (s->statem.hand_state == TLS_ST_CR_DID_VRFY || s->statem.hand_state == TLS_ST_SR_DID_VRFY)
		{
			memcpy(tls13tbs + TLS13_DID_TBS_PREAMBLE_SIZE, s->did_verify_hash,
				   s->did_verify_hash_len);
			hashlen = s->did_verify_hash_len;
		}
		else if (!ssl_handshake_hash(s,
									 tls13tbs + TLS13_DID_TBS_PREAMBLE_SIZE,
									 EVP_MAX_MD_SIZE, &hashlen))
		{
			/* SSLfatal() already called */
			return 0;
		}

		*hdata = tls13tbs;
		*hdatalen = TLS13_DID_TBS_PREAMBLE_SIZE + hashlen;
	}

	return 1;
}

int tls_construct_did_verify(SSL *s, WPACKET *pkt)
{

	EVP_PKEY *pkey = NULL;
	const EVP_MD *md = NULL;
	EVP_MD_CTX *mctx = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	size_t hdatalen = 0, siglen = 0;
	void *hdata;
	unsigned char *sig = NULL;
	unsigned char tls13tbs[TLS13_DID_TBS_PREAMBLE_SIZE + EVP_MAX_MD_SIZE];
	const SIGALG_LOOKUP *lu = s->s3.tmp.sigalg;

	if (lu == NULL || s->s3.tmp.did == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}
	pkey = s->s3.tmp.did->privatekey;

	if (pkey == NULL || !tls1_lookup_md(s->ctx, lu, &md))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	mctx = EVP_MD_CTX_new();
	if (mctx == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/* Get the data to be signed */
	if (!get_did_verify_tbs_data(s, tls13tbs, &hdata, &hdatalen))
	{
		/* SSLfatal() already called */
		goto err;
	}

	if (SSL_USE_SIGALGS(s) && !WPACKET_put_bytes_u16(pkt, lu->sigalg))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	if (EVP_DigestSignInit_ex(mctx, &pctx,
							  md == NULL ? NULL : EVP_MD_get0_name(md), s->ctx->libctx,
							  s->ctx->propq, pkey,
							  NULL) <= 0)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	if (lu->sig == EVP_PKEY_RSA_PSS)
	{
		if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
																											   RSA_PSS_SALTLEN_DIGEST) <= 0)
		{
			SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
			goto err;
		}
	}

	/*
	 * Here we *must* use EVP_DigestSign() because Ed25519/Ed448 does not
	 * support streaming via EVP_DigestSignUpdate/EVP_DigestSignFinal
	 */
	if (EVP_DigestSign(mctx, NULL, &siglen, hdata, hdatalen) <= 0)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}
	sig = OPENSSL_malloc(siglen);
	if (sig == NULL || EVP_DigestSign(mctx, sig, &siglen, hdata, hdatalen) <= 0)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

#ifndef OPENSSL_NO_GOST
	{
		int pktype = lu->sig;

		if (pktype == NID_id_GostR3410_2001 || pktype == NID_id_GostR3410_2012_256 || pktype == NID_id_GostR3410_2012_512)
			BUF_reverse(sig, NULL, siglen);
	}
#endif

	if (!WPACKET_sub_memcpy_u16(pkt, sig, siglen))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	/* Digest cached records and discard handshake buffer */
	if (!ssl3_digest_cached_records(s, 0))
	{
		/* SSLfatal() already called */
		goto err;
	}

	OPENSSL_free(sig);
	EVP_MD_CTX_free(mctx);
	return 1;
err:
	OPENSSL_free(sig);
	EVP_MD_CTX_free(mctx);
	return 0;
}

MSG_PROCESS_RETURN tls_process_did_verify(SSL *s, PACKET *pkt)
{
	/*EVP_PKEY *pkey = NULL;*/
	const unsigned char *data;
#ifndef OPENSSL_NO_GOST
	unsigned char *gost_data = NULL;
#endif
	MSG_PROCESS_RETURN ret = MSG_PROCESS_ERROR;
	int j;
	unsigned int len;
	EVP_PKEY *pkey; /* peer public key */
	const EVP_MD *md = NULL;
	size_t hdatalen = 0;
	void *hdata;
	unsigned char tls13tbs[TLS13_DID_TBS_PREAMBLE_SIZE + EVP_MAX_MD_SIZE];
	EVP_MD_CTX *mctx = EVP_MD_CTX_new();
	EVP_PKEY_CTX *pctx = NULL;

	if (mctx == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	pkey = s->session->peer_did_doc->authentication.pkey;

	if (pkey == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	/* "cert" in the function below means key type */
	if (ssl_cert_lookup_by_pkey(pkey, NULL) == NULL)
	{
		SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER,
				 SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE);
		goto err;
	}

	if (SSL_USE_SIGALGS(s))
	{
		unsigned int sigalg;

		if (!PACKET_get_net_2(pkt, &sigalg))
		{
			SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_PACKET);
			goto err;
		}
		if (tls12_check_peer_sigalg(s, sigalg, pkey) <= 0)
		{
			/* SSLfatal() already called */
			goto err;
		}
	}
	else if (!tls1_set_peer_legacy_sigalg(s, pkey))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	if (!tls1_lookup_md(s->ctx, s->s3.tmp.peer_sigalg, &md))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	if (SSL_USE_SIGALGS(s))
		OSSL_TRACE1(TLS, "USING TLSv1.2 HASH %s\n",
					md == NULL ? "n/a" : EVP_MD_get0_name(md));

		/* Check for broken implementations of GOST ciphersuites */
		/*
		 * If key is GOST and len is exactly 64 or 128, it is signature without
		 * length field (CryptoPro implementations at least till TLS 1.2)
		 */
#ifndef OPENSSL_NO_GOST
	if (!SSL_USE_SIGALGS(s) && ((PACKET_remaining(pkt) == 64 && (EVP_PKEY_get_id(pkey) == NID_id_GostR3410_2001 || EVP_PKEY_get_id(pkey) == NID_id_GostR3410_2012_256)) || (PACKET_remaining(pkt) == 128 && EVP_PKEY_get_id(pkey) == NID_id_GostR3410_2012_512)))
	{
		len = PACKET_remaining(pkt);
	}
	else
#endif
		if (!PACKET_get_net_2(pkt, &len))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		goto err;
	}

	if (!PACKET_get_bytes(pkt, &data, len))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		goto err;
	}

	if (!get_did_verify_tbs_data(s, tls13tbs, &hdata, &hdatalen))
	{
		/* SSLfatal() already called */
		goto err;
	}

	OSSL_TRACE1(TLS, "Using client verify alg %s\n",
				md == NULL ? "n/a" : EVP_MD_get0_name(md));

	if (EVP_DigestVerifyInit_ex(mctx, &pctx,
								md == NULL ? NULL : EVP_MD_get0_name(md), s->ctx->libctx,
								s->ctx->propq, pkey,
								NULL) <= 0)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}
#ifndef OPENSSL_NO_GOST
	{
		int pktype = EVP_PKEY_get_id(pkey);
		if (pktype == NID_id_GostR3410_2001 || pktype == NID_id_GostR3410_2012_256 || pktype == NID_id_GostR3410_2012_512)
		{
			if ((gost_data = OPENSSL_malloc(len)) == NULL)
			{
				SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
				goto err;
			}
			BUF_reverse(gost_data, data, len);
			data = gost_data;
		}
	}
#endif

	if (SSL_USE_PSS(s))
	{
		if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
																											   RSA_PSS_SALTLEN_DIGEST) <= 0)
		{
			SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
			goto err;
		}
	}
	j = EVP_DigestVerify(mctx, data, len, hdata, hdatalen);
	if (j <= 0)
	{
		SSLfatal(s, SSL_AD_DECRYPT_ERROR, SSL_R_BAD_SIGNATURE);
		goto err;
	}

	/*
	 * In TLSv1.3 on the client side we make sure we prepare the client
	 * certificate after the CertVerify instead of when we get the
	 * CertificateRequest. This is because in TLSv1.3 the CertificateRequest
	 * comes *before* the Certificate message. In TLSv1.2 it comes after. We
	 * want to make sure that SSL_get1_peer_certificate() will return the actual
	 * server certificate from the client_cert_cb callback.
	 */
	if (!s->server && (s->s3.tmp.ssi_req == 1 || s->s3.tmp.cert_req == 1))
		ret = MSG_PROCESS_CONTINUE_PROCESSING;
	else
		ret = MSG_PROCESS_CONTINUE_READING;
err:
	BIO_free(s->s3.handshake_buffer);
	s->s3.handshake_buffer = NULL;
	EVP_MD_CTX_free(mctx);
#ifndef OPENSSL_NO_GOST
	OPENSSL_free(gost_data);
#endif
	return ret;
}

/********************************************************
 *********************************************************
 **************** CLIENT METHODS  ***********************
 ********************************************************
 ********************************************************/

/*************************** SSI methods ***************************/

EXT_RETURN tls_construct_ctos_ssi_params(SSL *s, WPACKET *pkt,
										  unsigned int context, X509 *x, size_t chainidx)
{

#ifndef OPENSSL_NO_TLS1_3

	s->s3.ssi_params_sent = 0;

	if(s->did->key->did == NULL && s->did->key->did_len == 0 && 
	(s->ext.ssi_params.ssiauth != VC_AUTHN && s->ext.ssi_params.ssiauth != DID_AUTHN 
	|| s->ext.ssi_params.didmethods == NULL))
		return EXT_RETURN_NOT_SENT;

	/* if(s->ext.ssi_params.ssiauth == 0)
		return EXT_RETURN_NOT_SENT; */

	/* if (s->ext.ssi_params.didmethods == NULL || s->ext.peer_ssi_params.didmethods == 0)
		return EXT_RETURN_NOT_SENT; */

	if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ssi_params)
		/* Sub-packet for ssi params extension */
		|| !WPACKET_start_sub_packet_u16(pkt)
		/* peer SSI authentication method */
		|| !WPACKET_put_bytes_u8(pkt, s->ext.ssi_params.ssiauth)
		/* Sub-packet for the actual list */
		|| !WPACKET_start_sub_packet_u8(pkt)
		|| (/*s->ext.ssi_params.didmethods_len != 0 &&*/ !WPACKET_memcpy(pkt, s->ext.ssi_params.didmethods,
				s->ext.ssi_params.didmethods_len))
		/*|| !WPACKET_sub_memcpy_u8(pkt, s->ext.ssi_params.didmethods, s->ext.ssi_params.didmethods_len)*/
		|| !WPACKET_close(pkt)
		|| !WPACKET_close(pkt))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return EXT_RETURN_FAIL;
	}
	s->s3.ssi_params_sent = 1;
	return EXT_RETURN_SENT;
#else
	return EXT_RETURN_NOT_SENT;
#endif
}

int tls_parse_stoc_ssi_params(SSL *s, PACKET *pkt,
							   unsigned int context, X509 *x, size_t chainidx)
{

#ifndef OPENSSL_NO_TLS1_3
	PACKET did_methods;

	if (!PACKET_get_1(pkt, &s->ext.peer_ssi_params.ssiauth) ||
		!PACKET_as_length_prefixed_1(pkt, &did_methods) || PACKET_remaining(&did_methods) == 0)
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
		return 0;
	}

	if (!s->hit && !PACKET_memdup(&did_methods,
								  &s->ext.peer_ssi_params.didmethods,
								  &s->ext.peer_ssi_params.didmethods_len))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
		return 0;
	}
#endif

	return 1;
}

MSG_PROCESS_RETURN tls_process_ssi_request(SSL *s, PACKET *pkt)
{

	size_t i;

	/* Clear certificate validity flags */
	for (i = 0; i < SSL_PKEY_NUM; i++)
		s->s3.tmp.valid_flags[i] = 0;

	PACKET reqctx, extensions;
	RAW_EXTENSION *rawexts = NULL;

	if ((s->shutdown & SSL_SENT_SHUTDOWN) != 0)
	{
		/*
		 * We already sent close_notify. This can only happen in TLSv1.3
		 * post-handshake messages. We can't reasonably respond to this, so
		 * we just ignore it
		 */
		return MSG_PROCESS_FINISHED_READING;
	}

	/* OPENSSL_free(s->pha_context);
	s->pha_context = NULL;
	s->pha_context_len = 0; */

	if (!PACKET_get_length_prefixed_1(pkt, &reqctx) || !PACKET_memdup(&reqctx, &s->pha_context, &s->pha_context_len))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_get_length_prefixed_2(pkt, &extensions))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_LENGTH);
		return MSG_PROCESS_ERROR;
	}
	if (!tls_collect_extensions(s, &extensions, SSL_EXT_TLS1_3_SSI_REQUEST,
								&rawexts, NULL, 1) ||
		!tls_parse_all_extensions(s,
								  SSL_EXT_TLS1_3_SSI_REQUEST, rawexts, NULL, 0, 1))
	{
		/* SSLfatal() already called */
		OPENSSL_free(rawexts);
		return MSG_PROCESS_ERROR;
	}

	OPENSSL_free(rawexts);

	s->s3.auth_method = s->ext.peer_ssi_params.ssiauth;

	if (s->s3.ssi_params_sent &&
			(s->ext.ssi_params.ssiauth == VC_AUTHN || s->ext.ssi_params.ssiauth == DID_AUTHN) &&
			s->s3.auth_method != s->ext.ssi_params.ssiauth)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return MSG_PROCESS_ERROR;
	}

	if (!tls1_process_sigalgs(s))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_BAD_LENGTH);
		return MSG_PROCESS_ERROR;
	}

	/* Check client DID compatibility towards DID methods provided by the server */
	if (!tls1_process_did_methods(s))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_BAD_LENGTH);
		return MSG_PROCESS_ERROR;
	}

	if (PACKET_remaining(pkt) != 0)
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	/* we should setup a did to return.... */
	s->s3.tmp.ssi_req = 1;

	/*
	 * We don't prepare the client did yet. We wait until
	 * after the DidVerify message has been received.
	 */

	/*if (s->post_handshake_auth != SSL_PHA_REQUESTED)
		return MSG_PROCESS_CONTINUE_READING;

	return MSG_PROCESS_CONTINUE_PROCESSING;*/

	return MSG_PROCESS_CONTINUE_READING;
}

/*
 * Check a DID can be used for client authentication. Currently check
 * did exists.
 */
static int tls_check_client_did(SSL *s)
{
	/* If no suitable signature algorithm can't use did */
	if (!tls_choose_did_sigalg(s, 0) || s->s3.tmp.sigalg == NULL)
		return 0;

	return 1;
}

WORK_STATE tls_prepare_client_ssi(SSL *s, WORK_STATE wst)
{

	if (wst == WORK_MORE_A)
	{
		if (tls_check_client_did(s))
			return WORK_FINISHED_CONTINUE;
	}

	/* Shouldn't ever get here */
	SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
	return WORK_ERROR;
}

/*************************** VC methods ***************************/

MSG_PROCESS_RETURN tls_process_server_vc(SSL *s, PACKET *pkt)
{

	unsigned int vc_len, context;

	EVP_VC_CTX *ctx = NULL;
	EVP_VC *evp_vc = NULL;
	OSSL_PARAM params[13];
	size_t params_n = 0;

	unsigned char *vc_stream;

	s->session->peer_vc = OPENSSL_zalloc(sizeof(VC));
	if (s->session->peer_vc == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		return MSG_PROCESS_ERROR;
	}
	VC *vc = s->session->peer_vc;

	VC *tmp = OPENSSL_zalloc(sizeof(*tmp));
	if (tmp == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_get_1(pkt, &context) || context != 0)
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_get_net_2(pkt, &vc_len))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	vc_stream = OPENSSL_zalloc(sizeof(unsigned char) * vc_len);
	if (vc_stream == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_copy_bytes(pkt, vc_stream, vc_len) || PACKET_remaining(pkt) != 0)
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	evp_vc = EVP_VC_fetch(NULL, "VC", NULL);
	if (evp_vc == NULL)
		goto err;

	/* Create a context for the vc operation */
	ctx = EVP_VC_CTX_new(evp_vc);
	if (ctx == NULL)
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

	if (!EVP_VC_deserialize(ctx, vc_stream, params))
		goto err;

	vc->atContext = OPENSSL_strdup(tmp->atContext);
	vc->id = OPENSSL_strdup(tmp->id);
	vc->type = OPENSSL_strdup(tmp->type);
	vc->issuer = OPENSSL_strdup(tmp->issuer);
	vc->issuanceDate = OPENSSL_strdup(tmp->issuanceDate);
	vc->expirationDate = OPENSSL_strdup(tmp->expirationDate);
	vc->credentialSubject = OPENSSL_strdup(tmp->credentialSubject);
	vc->proofType = OPENSSL_strdup(tmp->proofType);
	vc->proofCreated = OPENSSL_strdup(tmp->proofCreated);
	vc->proofPurpose = OPENSSL_strdup(tmp->proofPurpose);
	vc->verificationMethod = OPENSSL_strdup(tmp->verificationMethod);
	vc->proofValue = OPENSSL_strdup(tmp->proofValue);

	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(ctx);
	OPENSSL_free(tmp);

	return MSG_PROCESS_CONTINUE_PROCESSING;

err:
	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(ctx);
	OPENSSL_free(tmp);

	return MSG_PROCESS_ERROR;
}

WORK_STATE tls_post_process_server_vc(SSL *s, WORK_STATE wst)
{

	VC *vc = s->session->peer_vc;
	EVP_VC_CTX *ctx_vc = NULL;
	EVP_VC *evp_vc = NULL;

	OSSL_PARAM params[13];
	size_t params_n = 0;
	/* VC_ISSUER *p;
	size_t i; */
	BIO *did_pubkey = NULL;
	EVP_PKEY *issuer_pubkey;

	EVP_DID_CTX *ctx_did = NULL;
	EVP_DID *evp_did = NULL;

	s->session->peer_did_doc = OPENSSL_zalloc(sizeof(DID_DOC));
	DID_DOC *diddoc = s->session->peer_did_doc;
	if (diddoc == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	evp_vc = EVP_VC_fetch(NULL, "VC", NULL);
	if (evp_vc == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	/* Create a context for the vc operation */
	ctx_vc = EVP_VC_CTX_new(evp_vc);
	if (ctx_vc == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (s->trusted_issuers == NULL)
		goto err;

	/*for(p = s->trusted_issuers, i = 0; i < s->trusted_issuers_num; i++, p++){
		if(strcmp(p->verificationMethod, vc->verificationMethod) == 0)
			issuer_pubkey = p->pubkey;
	}*/

	if(strcmp(s->trusted_issuers->verificationMethod, vc->verificationMethod) != 0){
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	issuer_pubkey = s->trusted_issuers->pubkey;

	if (issuer_pubkey == NULL)
		goto err;

	if (vc->atContext != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_CONTEXT, vc->atContext, 0);
	if (vc->id != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ID, vc->id, 0);
	if (vc->type != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_TYPE, vc->type, 0);
	if (vc->issuer != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUER, vc->issuer, 0);
	if (vc->issuanceDate != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUANCE_DATE, vc->issuanceDate, 0);
	if (vc->expirationDate != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_EXPIRATION_DATE, vc->expirationDate, 0);
	if (vc->credentialSubject != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_SUBJECT, vc->credentialSubject, 0);
	if (vc->proofType != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_TYPE, vc->proofType, 0);
	if (vc->proofCreated != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_CREATED, vc->proofCreated, 0);
	if (vc->proofPurpose != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_PURPOSE, vc->proofPurpose, 0);
	if (vc->verificationMethod != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_VERIFICATION_METHOD, vc->verificationMethod, 0);
	if (vc->proofValue != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_VALUE, vc->proofValue, 0);
	params[params_n] = OSSL_PARAM_construct_end();

	if (!EVP_VC_verify(ctx_vc, issuer_pubkey, params))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	evp_did = EVP_DID_fetch(NULL, "OTT", NULL);
	if (evp_did == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	/* Create a context for the DID operation */
	ctx_did = EVP_DID_CTX_new(evp_did);
	if (ctx_did == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	DID_DOC *tmp = OPENSSL_zalloc(sizeof(DID_DOC));
	if (tmp == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		return MSG_PROCESS_ERROR;
	}

	params_n = 0;

	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_CONTEXT, &tmp->atContext, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ID, &tmp->id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_CREATED, &tmp->created, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_ID, &tmp->authentication.id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_TYPE, &tmp->authentication.type, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_CONTROLLER, &tmp->authentication.controller, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_PKEY, &tmp->authentication.pkey_pem, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_ID, &tmp->assertion.id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_TYPE, &tmp->assertion.type, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_CONTROLLER, &tmp->assertion.controller, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_PKEY, &tmp->assertion.pkey_pem, 0);
	params[params_n] = OSSL_PARAM_construct_end();

	if (!EVP_DID_resolve(ctx_did, vc->credentialSubject, params) || tmp->authentication.pkey_pem == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	diddoc->atContext = OPENSSL_strdup(tmp->atContext);
	diddoc->id = OPENSSL_strdup(tmp->id);
	diddoc->created = OPENSSL_strdup(tmp->created);
	diddoc->authentication.id = OPENSSL_strdup(tmp->authentication.id);
	diddoc->authentication.type = OPENSSL_strdup(tmp->authentication.type);
	diddoc->authentication.controller = OPENSSL_strdup(tmp->authentication.controller);
	diddoc->authentication.pkey_pem = OPENSSL_strdup(tmp->authentication.pkey_pem);
	diddoc->assertion.id = OPENSSL_strdup(tmp->assertion.id);
	diddoc->assertion.type = OPENSSL_strdup(tmp->assertion.type);
	diddoc->assertion.controller = OPENSSL_strdup(tmp->assertion.controller);
	diddoc->assertion.pkey_pem = OPENSSL_strdup(tmp->assertion.pkey_pem);

	if ((did_pubkey = BIO_new_mem_buf(tmp->authentication.pkey_pem, -1)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_BIO_LIB);
		goto err;
	}

	if ((diddoc->authentication.pkey = PEM_read_bio_PUBKEY(did_pubkey, NULL, NULL, NULL)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PEM_LIB);
		goto err;
	}

	if ((did_pubkey = BIO_new_mem_buf(tmp->assertion.pkey_pem, -1)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_BIO_LIB);
		goto err;
	}

	if ((diddoc->assertion.pkey = PEM_read_bio_PUBKEY(did_pubkey, NULL, NULL, NULL)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PEM_LIB);
		goto err;
	}

	/* Save the current hash state for when we receive the DidVerify */
	if (!ssl_handshake_hash(s, s->did_verify_hash, sizeof(s->did_verify_hash),
							&s->did_verify_hash_len))
	{
		/* SSLfatal() already called */;
		goto err;
	}

	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(ctx_vc);
	EVP_DID_free(evp_did);
	EVP_DID_CTX_free(ctx_did);

	return WORK_FINISHED_CONTINUE;
err:

	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(ctx_vc);
	EVP_DID_free(evp_did);
	EVP_DID_CTX_free(ctx_did);

	return WORK_ERROR;
}

int tls_construct_client_vc(SSL *s, WPACKET *pkt)
{

	VC *vc = s->vc;

	EVP_VC_CTX *ctx = NULL;
	EVP_VC *evp_vc = NULL;
	OSSL_PARAM params[13];
	size_t params_n = 0;

	// OSSL_PROVIDER *provider = NULL;

	if (vc == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* PHA handling could be implemented, check client certificate */

	/* no context available, add 0-length context */
	if (!WPACKET_put_bytes_u8(pkt, 0))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	evp_vc = EVP_VC_fetch(NULL, "VC", NULL);
	if (evp_vc == NULL)
		goto err;

	/* Create a context for the vc operation */
	ctx = EVP_VC_CTX_new(evp_vc);
	if (ctx == NULL)
		goto err;

	if (vc->atContext != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_CONTEXT, vc->atContext, 0);
	if (vc->id != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ID, vc->id, 0);
	if (vc->type != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_TYPE, vc->type, 0);
	if (vc->issuer != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUER, vc->issuer, 0);
	if (vc->issuanceDate != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUANCE_DATE, vc->issuanceDate, 0);
	if (vc->expirationDate != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_EXPIRATION_DATE, vc->expirationDate, 0);
	if (vc->credentialSubject != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_SUBJECT, vc->credentialSubject, 0);
	if (vc->proofType != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_TYPE, vc->proofType, 0);
	if (vc->proofCreated != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_CREATED, vc->proofCreated, 0);
	if (vc->proofPurpose != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_PURPOSE, vc->proofPurpose, 0);
	if (vc->verificationMethod != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_VERIFICATION_METHOD, vc->verificationMethod, 0);
	if (vc->proofValue != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_VALUE, vc->proofValue, 0);
	params[params_n] = OSSL_PARAM_construct_end();

	s->vc_stream = EVP_VC_serialize(ctx, params);
	if (s->vc_stream == NULL)
		goto err;

	if (!WPACKET_sub_memcpy_u16(pkt, s->vc_stream, strlen(s->vc_stream)))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	if (SSL_IS_TLS13(s) && SSL_IS_FIRST_HANDSHAKE(s) && (!s->method->ssl3_enc->change_cipher_state(s, SSL3_CC_HANDSHAKE | SSL3_CHANGE_CIPHER_CLIENT_WRITE)))
	{
		/*
		 * This is a fatal error, which leaves enc_write_ctx in an inconsistent
		 * state and thus ssl3_send_alert may crash.
		 */
		SSLfatal(s, SSL_AD_NO_ALERT, SSL_R_CANNOT_CHANGE_CIPHER);
		goto err;
	}

	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(ctx);

	return 1;

err:

	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(ctx);

	return 0;
}

/*************************** DID methods ***************************/

MSG_PROCESS_RETURN tls_process_server_did(SSL *s, PACKET *pkt)
{

	OSSL_PARAM params[13];
	size_t params_n = 0;
	BIO *did_pubkey = NULL;
	char *server_did;
	unsigned int context, did_len;
	uint8_t method;

	EVP_DID_CTX *ctx_did = NULL;
	EVP_DID *evp_did = NULL;

	if (!PACKET_get_1(pkt, &context) || context != 0)
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_get_1(pkt, &method))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_get_net_2(pkt, &did_len))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	server_did = OPENSSL_malloc(did_len + 1);
	if (server_did == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!PACKET_copy_bytes(pkt, server_did, did_len) || PACKET_remaining(pkt) != 0)
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	s->session->peer_did_doc = OPENSSL_zalloc(sizeof(DID_DOC));
	DID_DOC *diddoc = s->session->peer_did_doc;
	if (diddoc == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	evp_did = EVP_DID_fetch(NULL, "OTT", NULL);
	if (evp_did == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	/* Create a context for the DID operation */
	ctx_did = EVP_DID_CTX_new(evp_did);
	if (ctx_did == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	DID_DOC *tmp = OPENSSL_zalloc(sizeof(DID_DOC));
	if (tmp == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		return MSG_PROCESS_ERROR;
	}

	params_n = 0;

	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_CONTEXT, &tmp->atContext, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ID, &tmp->id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_CREATED, &tmp->created, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_ID, &tmp->authentication.id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_TYPE, &tmp->authentication.type, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_CONTROLLER, &tmp->authentication.controller, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_PKEY, &tmp->authentication.pkey_pem, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_ID, &tmp->assertion.id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_TYPE, &tmp->assertion.type, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_CONTROLLER, &tmp->assertion.controller, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_PKEY, &tmp->assertion.pkey_pem, 0);
	params[params_n] = OSSL_PARAM_construct_end();

	if (!EVP_DID_resolve(ctx_did, server_did, params) || tmp->authentication.pkey_pem == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	diddoc->atContext = OPENSSL_strdup(tmp->atContext);
	diddoc->id = OPENSSL_strdup(tmp->id);
	diddoc->created = OPENSSL_strdup(tmp->created);
	diddoc->authentication.id = OPENSSL_strdup(tmp->authentication.id);
	diddoc->authentication.type = OPENSSL_strdup(tmp->authentication.type);
	diddoc->authentication.controller = OPENSSL_strdup(tmp->authentication.controller);
	diddoc->authentication.pkey_pem = OPENSSL_strdup(tmp->authentication.pkey_pem);
	diddoc->assertion.id = OPENSSL_strdup(tmp->assertion.id);
	diddoc->assertion.type = OPENSSL_strdup(tmp->assertion.type);
	diddoc->assertion.controller = OPENSSL_strdup(tmp->assertion.controller);
	diddoc->assertion.pkey_pem = OPENSSL_strdup(tmp->assertion.pkey_pem);

	if ((did_pubkey = BIO_new_mem_buf(tmp->authentication.pkey_pem, -1)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_BIO_LIB);
		goto err;
	}

	if ((diddoc->authentication.pkey = PEM_read_bio_PUBKEY(did_pubkey, NULL, NULL, NULL)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PEM_LIB);
		goto err;
	}

	if ((did_pubkey = BIO_new_mem_buf(tmp->assertion.pkey_pem, -1)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_BIO_LIB);
		goto err;
	}

	if ((diddoc->assertion.pkey = PEM_read_bio_PUBKEY(did_pubkey, NULL, NULL, NULL)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PEM_LIB);
		goto err;
	}

	/* Save the current hash state for when we receive the DidVerify */
	if (!ssl_handshake_hash(s, s->did_verify_hash, sizeof(s->did_verify_hash),
							&s->did_verify_hash_len))
	{
		/* SSLfatal() already called */;
		goto err;
	}

	OPENSSL_free(server_did);
	OPENSSL_free(tmp);
	EVP_DID_free(evp_did);
	EVP_DID_CTX_free(ctx_did);

	return MSG_PROCESS_CONTINUE_READING;
err:

	OPENSSL_free(server_did);
	OPENSSL_free(tmp);
	EVP_DID_free(evp_did);
	EVP_DID_CTX_free(ctx_did);

	return MSG_PROCESS_ERROR;
}

int tls_construct_client_did(SSL *s, WPACKET *pkt)
{

	/* PHA handling could be implemented, check client certificate */

	/* no context available, add 0-length context */
	if (!WPACKET_put_bytes_u8(pkt, 0))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* client's DID method*/
	if (!WPACKET_put_bytes_u8(pkt, s->did->key->did_method))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* The actual DID */
	if (!WPACKET_sub_memcpy_u16(pkt, s->did->key->did, s->did->key->did_len))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	if (SSL_IS_TLS13(s) && SSL_IS_FIRST_HANDSHAKE(s) && (!s->method->ssl3_enc->change_cipher_state(s, SSL3_CC_HANDSHAKE | SSL3_CHANGE_CIPHER_CLIENT_WRITE)))
	{
		/*
		 * This is a fatal error, which leaves enc_write_ctx in an inconsistent
		 * state and thus ssl3_send_alert may crash.
		 */
		SSLfatal(s, SSL_AD_NO_ALERT, SSL_R_CANNOT_CHANGE_CIPHER);
		return 0;
	}

	return 1;
}

/********************************************************
 ********************************************************
 **************** SERVER METHODS   **********************
 ********************************************************
 ********************************************************/

/*************************** SSI methods ***************************/

int tls_parse_ctos_ssi_params(SSL *s, PACKET *pkt,
							   unsigned int context, X509 *x, size_t chainidx)
{

#ifndef OPENSSL_NO_TLS1_3
	PACKET did_methods;

	if (!PACKET_get_1(pkt, &s->ext.peer_ssi_params.ssiauth) ||
		!PACKET_as_length_prefixed_1(pkt, &did_methods) || (s->ext.peer_ssi_params.ssiauth == 0 && PACKET_remaining(&did_methods) != 0)
		/*|| PACKET_remaining(&did_methods) == 0*/)
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
		return 0;
	}

	/*if (!PACKET_get_1(pkt, &s->ext.peer_ssi_params.ssiauth) ||
			!PACKET_copy_bytes(pkt, s->ext.peer_ssi_params.didmethods, s->ext.peer_ssi_params.didmethods_len) ||
			PACKET_remaining(pkt) != 0)
		{
			SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
			return 0;
		}*/

	if (!s->hit && !PACKET_memdup(&did_methods,
								  &s->ext.peer_ssi_params.didmethods,
								  &s->ext.peer_ssi_params.didmethods_len))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	s->s3.ssi_params_received = 1;

#endif

	return 1;
}

EXT_RETURN tls_construct_stoc_ssi_params(SSL *s, WPACKET *pkt,
										  unsigned int context, X509 *x, size_t chainidx)
{
#ifndef OPENSSL_NO_TLS1_3

	if (s->ext.ssi_params.didmethods == NULL || s->ext.ssi_params.didmethods_len == 0)
		return EXT_RETURN_NOT_SENT;

	uint8_t *didmethods;
	size_t didmethodslen;

	s->s3.ssi_params_sent = 0;

	if (s->shared_didmethods != NULL)
	{
		didmethods = s->shared_didmethods;
		didmethodslen = s->shared_didmethodslen;
	}
	else
	{
		didmethods = s->ext.ssi_params.didmethods;
		didmethodslen = s->ext.ssi_params.didmethods_len;
	}

	if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ssi_params)
		/* Sub-packet for did methods extension */
		|| !WPACKET_start_sub_packet_u16(pkt)
		/* peer SSI authentication method */
		|| !WPACKET_put_bytes_u8(pkt, s->ext.ssi_params.ssiauth)
		/* Sub-packet for the actual list */
		|| !WPACKET_sub_memcpy_u8(pkt, didmethods, didmethodslen) || !WPACKET_close(pkt))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return EXT_RETURN_FAIL;
	}
	return EXT_RETURN_SENT;
#else
	return EXT_RETURN_NOT_SENT;
#endif
}

/*************************** VC methods ***************************/

int tls_construct_ssi_request(SSL *s, WPACKET *pkt)
{

	/* Request context must be 0-length, unless used for PHA */
	if (!WPACKET_put_bytes_u8(pkt, 0))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	if (!tls_construct_extensions(s, pkt, SSL_EXT_TLS1_3_SSI_REQUEST, NULL,
								  0))
	{
		/* SSLfatal() already called */
		return 0;
	}

	/* We don't need s->vcreqs_sent here, since it is used with SSL_VERIFY_CLIENT_ONCE */
	s->s3.tmp.ssi_request = 1;

	return 1;
}

int tls_construct_server_vc(SSL *s, WPACKET *pkt)
{

	VC *vc = s->s3.tmp.vc;
	EVP_VC_CTX *ctx = NULL;
	EVP_VC *evp_vc = NULL;
	OSSL_PARAM params[13];
	size_t params_n = 0;

	// OSSL_PROVIDER *provider = NULL;

	/* 0-length context for server VC message */
	if (SSL_IS_TLS13(s) && !WPACKET_put_bytes_u8(pkt, 0))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/*provider = OSSL_PROVIDER_load(NULL, "ssi");
	if (provider == NULL) {
		printf("SSI provider load failed\n");
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}*/

	evp_vc = EVP_VC_fetch(NULL, "VC", NULL);
	if (evp_vc == NULL)
		goto err;

	/* Create a context for the vc operation */
	ctx = EVP_VC_CTX_new(evp_vc);
	if (ctx == NULL)
		goto err;

	if (vc->atContext != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_CONTEXT, vc->atContext, 0);
	if (vc->id != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ID, vc->id, 0);
	if (vc->type != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_TYPE, vc->type, 0);
	if (vc->issuer != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUER, vc->issuer, 0);
	if (vc->issuanceDate != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUANCE_DATE, vc->issuanceDate, 0);
	if (vc->expirationDate != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_EXPIRATION_DATE, vc->expirationDate, 0);
	if (vc->credentialSubject != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_SUBJECT, vc->credentialSubject, 0);
	if (vc->proofType != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_TYPE, vc->proofType, 0);
	if (vc->proofCreated != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_CREATED, vc->proofCreated, 0);
	if (vc->proofPurpose != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_PURPOSE, vc->proofPurpose, 0);
	if (vc->verificationMethod != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_VERIFICATION_METHOD, vc->verificationMethod, 0);
	if (vc->proofValue != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_VALUE, vc->proofValue, 0);
	params[params_n] = OSSL_PARAM_construct_end();

	s->s3.tmp.vc_stream = EVP_VC_serialize(ctx, params);
	if (s->s3.tmp.vc_stream == NULL)
		goto err;

	if (!WPACKET_sub_memcpy_u16(pkt, s->s3.tmp.vc_stream,
								strlen(s->s3.tmp.vc_stream)))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(ctx);

	return 1;

err:

	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(ctx);

	return 0;
}

MSG_PROCESS_RETURN tls_process_client_vc(SSL *s, PACKET *pkt)
{

	unsigned int vc_len;
	PACKET context;
	EVP_VC_CTX *ctx_vc = NULL;
	EVP_VC *evp_vc = NULL;
	OSSL_PARAM params[13];
	size_t params_n = 0;
	/* VC_ISSUER *p;
	size_t i; */
	EVP_PKEY *issuer_pubkey;
	BIO *did_pubkey = NULL;

	unsigned char *vc_stream;

	EVP_DID_CTX *ctx_did = NULL;
	EVP_DID *evp_did = NULL;

	s->session->peer_did_doc = OPENSSL_zalloc(sizeof(DID_DOC));
	DID_DOC *diddoc = s->session->peer_did_doc;
	if (diddoc == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	s->session->peer_vc = OPENSSL_zalloc(sizeof(VC));
	if (s->session->peer_vc == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		return MSG_PROCESS_ERROR;
	}
	VC *vc = s->session->peer_vc;

	VC *tmp_vc = OPENSSL_zalloc(sizeof(VC));
	if (tmp_vc == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return MSG_PROCESS_ERROR;
	}

	s->statem.enc_read_state = ENC_READ_STATE_VALID;

	if ((!PACKET_get_length_prefixed_1(pkt, &context) || (s->pha_context == NULL && PACKET_remaining(&context) != 0) || (s->pha_context != NULL && !PACKET_equal(&context, s->pha_context, s->pha_context_len))))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_INVALID_CONTEXT);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_get_net_2(pkt, &vc_len))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	vc_stream = OPENSSL_malloc(sizeof(unsigned char) * vc_len);
	if (vc_stream == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_copy_bytes(pkt, vc_stream, vc_len) || PACKET_remaining(pkt) != 0)
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	evp_vc = EVP_VC_fetch(NULL, "VC", NULL);
	if (evp_vc == NULL)
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	/* Create a context for the vc operation */
	ctx_vc = EVP_VC_CTX_new(evp_vc);
	if (ctx_vc == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_CONTEXT, &tmp_vc->atContext, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_ID, &tmp_vc->id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_TYPE, &tmp_vc->type, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_ISSUER, &tmp_vc->issuer, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_ISSUANCE_DATE, &tmp_vc->issuanceDate, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_EXPIRATION_DATE, &tmp_vc->expirationDate, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_SUBJECT, &tmp_vc->credentialSubject, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_PROOF_TYPE, &tmp_vc->proofType, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_PROOF_CREATED, &tmp_vc->proofCreated, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_PROOF_PURPOSE, &tmp_vc->proofPurpose, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_VERIFICATION_METHOD, &tmp_vc->verificationMethod, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_PROOF_VALUE, &tmp_vc->proofValue, 0);
	params[params_n] = OSSL_PARAM_construct_end();

	if (!EVP_VC_deserialize(ctx_vc, vc_stream, params))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	vc->atContext = OPENSSL_strdup(tmp_vc->atContext);
	vc->id = OPENSSL_strdup(tmp_vc->id);
	vc->type = OPENSSL_strdup(tmp_vc->type);
	vc->issuer = OPENSSL_strdup(tmp_vc->issuer);
	vc->issuanceDate = OPENSSL_strdup(tmp_vc->issuanceDate);
	vc->expirationDate = OPENSSL_strdup(tmp_vc->expirationDate);
	vc->credentialSubject = OPENSSL_strdup(tmp_vc->credentialSubject);
	vc->proofType = OPENSSL_strdup(tmp_vc->proofType);
	vc->proofCreated = OPENSSL_strdup(tmp_vc->proofCreated);
	vc->proofPurpose = OPENSSL_strdup(tmp_vc->proofPurpose);
	vc->verificationMethod = OPENSSL_strdup(tmp_vc->verificationMethod);
	vc->proofValue = OPENSSL_strdup(tmp_vc->proofValue);

	EVP_VC_CTX_free(ctx_vc);

	ctx_vc = EVP_VC_CTX_new(evp_vc);
	if (ctx_vc == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (s->trusted_issuers == NULL)
		goto err;

	/*for(i = 0, p = s->trusted_issuers; i < s->trusted_issuers_num; i++, p++){
		if(strcmp(p->verificationMethod, vc->verificationMethod) == 0)
			issuer_pubkey = p->pubkey;
	}*/

	if(strcmp(s->trusted_issuers->verificationMethod, vc->verificationMethod) != 0){
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	issuer_pubkey = s->trusted_issuers->pubkey;
	if (issuer_pubkey == NULL)
		goto err;

	params_n = 0;

	if (vc->atContext != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_CONTEXT, vc->atContext, 0);
	if (vc->id != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ID, vc->id, 0);
	if (vc->type != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_TYPE, vc->type, 0);
	if (vc->issuer != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUER, vc->issuer, 0);
	if (vc->issuanceDate != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUANCE_DATE, vc->issuanceDate, 0);
	if (vc->expirationDate != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_EXPIRATION_DATE, vc->expirationDate, 0);
	if (vc->credentialSubject != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_SUBJECT, vc->credentialSubject, 0);
	if (vc->proofType != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_TYPE, vc->proofType, 0);
	if (vc->proofCreated != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_CREATED, vc->proofCreated, 0);
	if (vc->proofPurpose != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_PURPOSE, vc->proofPurpose, 0);
	if (vc->verificationMethod != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_VERIFICATION_METHOD, vc->verificationMethod, 0);
	if (vc->proofValue != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_VALUE, vc->proofValue, 0);
	params[params_n] = OSSL_PARAM_construct_end();

	if (!EVP_VC_verify(ctx_vc, issuer_pubkey, params))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	evp_did = EVP_DID_fetch(NULL, "OTT", NULL);
	if (evp_did == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	/* Create a context for the vc operation */
	ctx_did = EVP_DID_CTX_new(evp_did);
	if (ctx_did == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	DID_DOC *tmp_did = OPENSSL_zalloc(sizeof(DID_DOC));
	if (tmp_did == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		return MSG_PROCESS_ERROR;
	}

	params_n = 0;

	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_CONTEXT, &tmp_did->atContext, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ID, &tmp_did->id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_CREATED, &tmp_did->created, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_ID, &tmp_did->authentication.id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_TYPE, &tmp_did->authentication.type, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_CONTROLLER, &tmp_did->authentication.controller, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_PKEY, &tmp_did->authentication.pkey_pem, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_ID, &tmp_did->assertion.id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_TYPE, &tmp_did->assertion.type, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_CONTROLLER, &tmp_did->assertion.controller, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_PKEY, &tmp_did->assertion.pkey_pem, 0);
	params[params_n] = OSSL_PARAM_construct_end();

	if (!EVP_DID_resolve(ctx_did, vc->credentialSubject, params) || tmp_did->authentication.pkey_pem == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	diddoc->atContext = OPENSSL_strdup(tmp_did->atContext);
	diddoc->id = OPENSSL_strdup(tmp_did->id);
	diddoc->created = OPENSSL_strdup(tmp_did->created);
	diddoc->authentication.id = OPENSSL_strdup(tmp_did->authentication.id);
	diddoc->authentication.type = OPENSSL_strdup(tmp_did->authentication.type);
	diddoc->authentication.controller = OPENSSL_strdup(tmp_did->authentication.controller);
	diddoc->authentication.pkey_pem = OPENSSL_strdup(tmp_did->authentication.pkey_pem);
	diddoc->assertion.id = OPENSSL_strdup(tmp_did->assertion.id);
	diddoc->assertion.type = OPENSSL_strdup(tmp_did->assertion.type);
	diddoc->assertion.controller = OPENSSL_strdup(tmp_did->assertion.controller);
	diddoc->assertion.pkey_pem = OPENSSL_strdup(tmp_did->assertion.pkey_pem);

	if ((did_pubkey = BIO_new_mem_buf(tmp_did->authentication.pkey_pem, -1)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_BIO_LIB);
		goto err;
	}

	if ((diddoc->authentication.pkey = PEM_read_bio_PUBKEY(did_pubkey, NULL, NULL, NULL)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PEM_LIB);
		goto err;
	}

	if ((did_pubkey = BIO_new_mem_buf(tmp_did->assertion.pkey_pem, -1)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_BIO_LIB);
		goto err;
	}

	if ((diddoc->assertion.pkey =
			 PEM_read_bio_PUBKEY(did_pubkey, NULL, NULL, NULL)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PEM_LIB);
		goto err;
	}

	if (!ssl3_digest_cached_records(s, 1))
	{
		/* SSLfatal() already called */
		goto err;
	}

	/* Save the current hash state for when we receive the DidVerify */
	if (!ssl_handshake_hash(s, s->did_verify_hash, sizeof(s->did_verify_hash),
							&s->did_verify_hash_len))
	{
		/* SSLfatal() already called */;
		goto err;
	}

	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(ctx_vc);
	EVP_DID_free(evp_did);
	EVP_DID_CTX_free(ctx_did);

	return MSG_PROCESS_CONTINUE_READING;

err:

	EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(ctx_vc);
	EVP_DID_free(evp_did);
	EVP_DID_CTX_free(ctx_did);

	return MSG_PROCESS_ERROR;
}

/*************************** DID methods ***************************/

int tls_construct_server_did(SSL *s, WPACKET *pkt)
{

	DID_PKEY *dpk = s->s3.tmp.did;

	if (dpk == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* 0-length context for server Did message */
	if (SSL_IS_TLS13(s) && !WPACKET_put_bytes_u8(pkt, 0))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* 1 byte reserved for the did method of server did*/
	if (!WPACKET_put_bytes_u8(pkt, dpk->did_method))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* contains the actual did */
	if (!WPACKET_sub_memcpy_u16(pkt, dpk->did, dpk->did_len))
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	return 1;
}

MSG_PROCESS_RETURN tls_process_client_did(SSL *s, PACKET *pkt)
{
	OSSL_PARAM params[13];
	size_t params_n = 0;
	BIO *did_pubkey = NULL;
	char *client_did;
	size_t context, did_len;
	uint8_t method;

	EVP_DID_CTX *ctx_did = NULL;
	EVP_DID *evp_did = NULL;

	s->statem.enc_read_state = ENC_READ_STATE_VALID;

	if ((!PACKET_get_length_prefixed_1(pkt, &context) || (s->pha_context == NULL && PACKET_remaining(&context) != 0) || (s->pha_context != NULL && !PACKET_equal(&context, s->pha_context, s->pha_context_len))))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_INVALID_CONTEXT);
		goto err;
	}

	if (!PACKET_get_1(pkt, &method))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_TOO_SHORT);
		goto err;
	}

	if (!PACKET_get_net_2(pkt, &did_len))
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	client_did = OPENSSL_malloc(did_len + 1);
	if (client_did == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!PACKET_copy_bytes(pkt, client_did, did_len) || PACKET_remaining(pkt) != 0)
	{
		SSLfatal(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	s->session->peer_did_doc = OPENSSL_zalloc(sizeof(DID_DOC));
	DID_DOC *diddoc = s->session->peer_did_doc;
	if (diddoc == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	evp_did = EVP_DID_fetch(NULL, "OTT", NULL);
	if (evp_did == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	/* Create a context for the DID operation */
	ctx_did = EVP_DID_CTX_new(evp_did);
	if (ctx_did == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	DID_DOC *tmp = OPENSSL_zalloc(sizeof(DID_DOC));
	if (tmp == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	params_n = 0;

	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_CONTEXT, &tmp->atContext, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ID, &tmp->id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_CREATED, &tmp->created, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_ID, &tmp->authentication.id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_TYPE, &tmp->authentication.type, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_CONTROLLER, &tmp->authentication.controller, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_AUTHN_METH_PKEY, &tmp->authentication.pkey_pem, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_ID, &tmp->assertion.id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_TYPE, &tmp->assertion.type, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_CONTROLLER, &tmp->assertion.controller, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_DID_PARAM_ASSRTN_METH_PKEY, &tmp->assertion.pkey_pem, 0);
	params[params_n] = OSSL_PARAM_construct_end();

	if (!EVP_DID_resolve(ctx_did, client_did, params) || tmp->authentication.pkey_pem == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	diddoc->atContext = OPENSSL_strdup(tmp->atContext);
	diddoc->id = OPENSSL_strdup(tmp->id);
	diddoc->created = OPENSSL_strdup(tmp->created);
	diddoc->authentication.id = OPENSSL_strdup(tmp->authentication.id);
	diddoc->authentication.type = OPENSSL_strdup(tmp->authentication.type);
	diddoc->authentication.controller = OPENSSL_strdup(tmp->authentication.controller);
	diddoc->authentication.pkey_pem = OPENSSL_strdup(tmp->authentication.pkey_pem);
	diddoc->assertion.id = OPENSSL_strdup(tmp->assertion.id);
	diddoc->assertion.type = OPENSSL_strdup(tmp->assertion.type);
	diddoc->assertion.controller = OPENSSL_strdup(tmp->assertion.controller);
	diddoc->assertion.pkey_pem = OPENSSL_strdup(tmp->assertion.pkey_pem);

	if ((did_pubkey = BIO_new_mem_buf(tmp->authentication.pkey_pem, -1)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_BIO_LIB);
		goto err;
	}

	if ((diddoc->authentication.pkey = PEM_read_bio_PUBKEY(did_pubkey, NULL, NULL, NULL)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PEM_LIB);
		goto err;
	}

	if ((did_pubkey = BIO_new_mem_buf(tmp->assertion.pkey_pem, -1)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_BIO_LIB);
		goto err;
	}

	if ((diddoc->assertion.pkey = PEM_read_bio_PUBKEY(did_pubkey, NULL, NULL, NULL)) == NULL)
	{
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PEM_LIB);
		goto err;
	}

	/*
	 * Freeze the handshake buffer
	 */
	if (!ssl3_digest_cached_records(s, 1))
	{
		/* SSLfatal() already called */
		goto err;
	}

	/* Save the current hash state for when we receive the DidVerify */
	if (!ssl_handshake_hash(s, s->did_verify_hash, sizeof(s->did_verify_hash),
							&s->did_verify_hash_len))
	{
		/* SSLfatal() already called */;
		goto err;
	}

	OPENSSL_free(client_did);
	OPENSSL_free(tmp);
	EVP_DID_free(evp_did);
	EVP_DID_CTX_free(ctx_did);

	return MSG_PROCESS_CONTINUE_READING;
err:

	OPENSSL_free(client_did);
	OPENSSL_free(tmp);
	EVP_DID_free(evp_did);
	EVP_DID_CTX_free(ctx_did);

	return MSG_PROCESS_ERROR;
}
