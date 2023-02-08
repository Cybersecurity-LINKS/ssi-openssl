/*
 * supported_dids.c
 *
 *  Created on: Jun 8, 2022
 *      Author: leonardo
 */

#include <openssl/tls1.h>
#include <ssl/ssl_local_did.h>

#include "statem_local_did.h"
#include "/home/leonardo/Desktop/C_CRUD/did_method.h"

int init_did(SSL *s, unsigned int context) {

	/* Clear any supported did method received */
	OPENSSL_free(s->ext.peer_supporteddidmethods);
	s->ext.peer_supporteddidmethods = NULL;
	s->ext.peer_supporteddidmethods_len = 0;

	return 1;
}

/*
 * Size of the to-be-signed TLS13 data, without the hash size itself:
 * 64 bytes of value 32, 33 context bytes, 1 byte separator
 */
#define TLS13_DID_TBS_START_SIZE            64
#define TLS13_DID_TBS_PREAMBLE_SIZE         (TLS13_DID_TBS_START_SIZE + 25 + 1)

static int get_did_verify_tbs_data(SSL *s, unsigned char *tls13tbs,
		void **hdata, size_t *hdatalen) {
	static const char servercontext[] = "TLS 1.3, server DidVerify";
	static const char clientcontext[] = "TLS 1.3, client DidVerify";

	if (SSL_IS_TLS13(s)) {
		size_t hashlen;

		/* Set the first 64 bytes of to-be-signed data to octet 32 */
		memset(tls13tbs, 32, TLS13_DID_TBS_START_SIZE);
		/* This copies the 33 bytes of context plus the 0 separator byte */
		if (s->statem.hand_state == TLS_ST_CR_DID_VRFY
				|| s->statem.hand_state == TLS_ST_SW_DID_VRFY)
			strcpy((char*) tls13tbs + TLS13_DID_TBS_START_SIZE, servercontext);
		else
			strcpy((char*) tls13tbs + TLS13_DID_TBS_START_SIZE, clientcontext);

		/*
		 * If we're currently reading then we need to use the saved handshake
		 * hash value. We can't use the current handshake hash state because
		 * that includes the CertVerify itself.
		 */
		if (s->statem.hand_state == TLS_ST_CR_DID_VRFY
				|| s->statem.hand_state == TLS_ST_SR_DID_VRFY) {
			memcpy(tls13tbs + TLS13_DID_TBS_PREAMBLE_SIZE, s->did_verify_hash,
					s->did_verify_hash_len);
			hashlen = s->did_verify_hash_len;
		} else if (!ssl_handshake_hash(s,
				tls13tbs + TLS13_DID_TBS_PREAMBLE_SIZE,
				EVP_MAX_MD_SIZE, &hashlen)) {
			/* SSLfatal() already called */
			return 0;
		}

		*hdata = tls13tbs;
		*hdatalen = TLS13_DID_TBS_PREAMBLE_SIZE + hashlen;
	}

	return 1;
}

int tls_construct_did_verify(SSL *s, WPACKET *pkt) {

	EVP_PKEY *pkey = NULL;
	const EVP_MD *md = NULL;
	EVP_MD_CTX *mctx = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	size_t hdatalen = 0, siglen = 0;
	void *hdata;
	unsigned char *sig = NULL;
	unsigned char tls13tbs[TLS13_DID_TBS_PREAMBLE_SIZE + EVP_MAX_MD_SIZE];
	const SIGALG_LOOKUP *lu = s->s3.tmp.sigalg;

	if (lu == NULL || s->s3.tmp.did == NULL) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}
	pkey = s->s3.tmp.did->privatekey;

	if (pkey == NULL || !tls1_lookup_md(s->ctx, lu, &md)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	mctx = EVP_MD_CTX_new();
	if (mctx == NULL) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/* Get the data to be signed */
	if (!get_did_verify_tbs_data(s, tls13tbs, &hdata, &hdatalen)) {
		/* SSLfatal() already called */
		goto err;
	}

	if (SSL_USE_SIGALGS(s) && !WPACKET_put_bytes_u16(pkt, lu->sigalg)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	if (EVP_DigestSignInit_ex(mctx, &pctx,
			md == NULL ? NULL : EVP_MD_get0_name(md), s->ctx->libctx,
			s->ctx->propq, pkey,
			NULL) <= 0) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

	if (lu->sig == EVP_PKEY_RSA_PSS) {
		if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
				|| EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
				RSA_PSS_SALTLEN_DIGEST) <= 0) {
			SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
			goto err;
		}
	}

	/*
	 * Here we *must* use EVP_DigestSign() because Ed25519/Ed448 does not
	 * support streaming via EVP_DigestSignUpdate/EVP_DigestSignFinal
	 */
	if (EVP_DigestSign(mctx, NULL, &siglen, hdata, hdatalen) <= 0) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}
	sig = OPENSSL_malloc(siglen);
	if (sig == NULL
			|| EVP_DigestSign(mctx, sig, &siglen, hdata, hdatalen) <= 0) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}

#ifndef OPENSSL_NO_GOST
	{
		int pktype = lu->sig;

		if (pktype == NID_id_GostR3410_2001
				|| pktype == NID_id_GostR3410_2012_256
				|| pktype == NID_id_GostR3410_2012_512)
			BUF_reverse(sig, NULL, siglen);
	}
#endif

	if (!WPACKET_sub_memcpy_u16(pkt, sig, siglen)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	/* Digest cached records and discard handshake buffer */
	if (!ssl3_digest_cached_records(s, 0)) {
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


MSG_PROCESS_RETURN tls_process_did_verify(SSL *s, PACKET *pkt) {

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

	if (mctx == NULL) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	pkey = s->session->peer_did_pubkey;

	if (pkey == NULL) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	/* "cert" in the function below means key type */
	if (ssl_cert_lookup_by_pkey(pkey, NULL) == NULL) {
		SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER,
				SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE);
		goto err;
	}

	if (SSL_USE_SIGALGS(s)) {
		unsigned int sigalg;

		if (!PACKET_get_net_2(pkt, &sigalg)) {
			SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_PACKET);
			goto err;
		}
		if (tls12_check_peer_sigalg(s, sigalg, pkey) <= 0) {
			/* SSLfatal() already called */
			goto err;
		}
	} else if (!tls1_set_peer_legacy_sigalg(s, pkey)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	if (!tls1_lookup_md(s->ctx, s->s3.tmp.peer_sigalg, &md)) {
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
	if (!SSL_USE_SIGALGS(s)
			&& ((PACKET_remaining(pkt) == 64
					&& (EVP_PKEY_get_id(pkey) == NID_id_GostR3410_2001
							|| EVP_PKEY_get_id(pkey)
									== NID_id_GostR3410_2012_256))
					|| (PACKET_remaining(pkt) == 128
							&& EVP_PKEY_get_id(pkey)
									== NID_id_GostR3410_2012_512))) {
		len = PACKET_remaining(pkt);
	} else
#endif
	if (!PACKET_get_net_2(pkt, &len)) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		goto err;
	}

	if (!PACKET_get_bytes(pkt, &data, len)) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		goto err;
	}

	if (!get_did_verify_tbs_data(s, tls13tbs, &hdata, &hdatalen)) {
		/* SSLfatal() already called */
		goto err;
	}

	OSSL_TRACE1(TLS, "Using client verify alg %s\n",
			md == NULL ? "n/a" : EVP_MD_get0_name(md));

	if (EVP_DigestVerifyInit_ex(mctx, &pctx,
			md == NULL ? NULL : EVP_MD_get0_name(md), s->ctx->libctx,
			s->ctx->propq, pkey,
			NULL) <= 0) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
		goto err;
	}
#ifndef OPENSSL_NO_GOST
	{
		int pktype = EVP_PKEY_get_id(pkey);
		if (pktype == NID_id_GostR3410_2001
				|| pktype == NID_id_GostR3410_2012_256
				|| pktype == NID_id_GostR3410_2012_512) {
			if ((gost_data = OPENSSL_malloc(len)) == NULL) {
				SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
				goto err;
			}
			BUF_reverse(gost_data, data, len);
			data = gost_data;
		}
	}
#endif

	if (SSL_USE_PSS(s)) {
		if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
				|| EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
				RSA_PSS_SALTLEN_DIGEST) <= 0) {
			SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
			goto err;
		}
	}
	j = EVP_DigestVerify(mctx, data, len, hdata, hdatalen);
	if (j <= 0) {
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
	if (!s->server && (s->s3.tmp.did_req == 1 || s->s3.tmp.cert_req == 1))
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

EXT_RETURN tls_construct_ctos_supported_did_methods(SSL *s, WPACKET *pkt,
		unsigned int context, X509 *x, size_t chainidx) {

#ifndef OPENSSL_NO_TLS1_3

	s->s3.did_sent = 0;

	if (s->ext.supporteddidmethods == NULL || s->ext.supporteddidmethods_len == 0)
		return EXT_RETURN_NOT_SENT;

	if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_supported_did_methods)
	/* Sub-packet for supported_dids extension */
	|| !WPACKET_start_sub_packet_u16(pkt)
	/* Sub-packet for the actual list */
	|| !WPACKET_sub_memcpy_u8(pkt, s->ext.supporteddidmethods, s->ext.supporteddidmethods_len)
			|| !WPACKET_close(pkt)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return EXT_RETURN_FAIL;
	}
	s->s3.did_sent = 1;
	return EXT_RETURN_SENT;
#else
	return EXT_RETURN_NOT_SENT;
#endif
}

int tls_parse_stoc_supported_did_methods(SSL *s, PACKET *pkt,
		unsigned int context, X509 *x, size_t chainidx) {

#ifndef OPENSSL_NO_TLS1_3
	PACKET supported_did_methods;

	if (!PACKET_as_length_prefixed_1(pkt, &supported_did_methods)
			|| PACKET_remaining(&supported_did_methods) == 0) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
		return 0;
	}

	if (!s->hit
			&& !PACKET_memdup(&supported_did_methods,
					&s->ext.peer_supporteddidmethods,
					&s->ext.peer_supporteddidmethods_len)) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
		return 0;
	}
#endif

	return 1;
}

MSG_PROCESS_RETURN tls_process_did_request(SSL *s, PACKET *pkt) {

	size_t i;

	s->auth_method = DID_AUTHN;
	/* Clear certificate validity flags */
	for (i = 0; i < SSL_PKEY_NUM; i++)
		s->s3.tmp.valid_flags[i] = 0;

	PACKET reqctx, extensions;
	RAW_EXTENSION *rawexts = NULL;

	if ((s->shutdown & SSL_SENT_SHUTDOWN) != 0) {
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

	if (!PACKET_get_length_prefixed_1(pkt, &reqctx)
			|| !PACKET_memdup(&reqctx, &s->pha_context, &s->pha_context_len)) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_get_length_prefixed_2(pkt, &extensions)) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_LENGTH);
		return MSG_PROCESS_ERROR;
	}
	if (!tls_collect_extensions(s, &extensions, SSL_EXT_TLS1_3_DID_REQUEST,
			&rawexts, NULL, 1) || !tls_parse_all_extensions(s,
	SSL_EXT_TLS1_3_DID_REQUEST, rawexts, NULL, 0, 1)) {
		/* SSLfatal() already called */
		OPENSSL_free(rawexts);
		return MSG_PROCESS_ERROR;
	}

	OPENSSL_free(rawexts);

	if (!tls1_process_sigalgs(s)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_BAD_LENGTH);
		return MSG_PROCESS_ERROR;
	}

	/* Check client did compatibility towards did methods provided by the server */
	if (!tls1_process_supported_did_methods(s)){
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_BAD_LENGTH);
		return MSG_PROCESS_ERROR;
	}

	if (PACKET_remaining(pkt) != 0) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	/* we should setup a did to return.... */
	s->s3.tmp.did_req = 1;

	/*
	 * We don't prepare the client did yet. We wait until
	 * after the DidVerify message has been received.
	 */

	/*if (s->post_handshake_auth != SSL_PHA_REQUESTED)
		return MSG_PROCESS_CONTINUE_READING;

	return MSG_PROCESS_CONTINUE_PROCESSING;*/

	return MSG_PROCESS_CONTINUE_READING;
}

MSG_PROCESS_RETURN tls_process_server_did(SSL *s, PACKET *pkt) {

	did_document_ *didDocument = NULL;
	unsigned int did_len, context, method;
	unsigned char server_did[100];
	BIO *pubkey;

	didDocument = calloc(1, sizeof(did_document_));
	if (didDocument == NULL) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return MSG_PROCESS_ERROR;
	}

	did_document_init(didDocument);

	if (!PACKET_get_1(pkt, &context) || context != 0) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_get_1(pkt, &method)) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_get_net_2(pkt, &did_len)
			|| !PACKET_copy_bytes(pkt, server_did, did_len)
			|| PACKET_remaining(pkt) != 0) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
		return MSG_PROCESS_ERROR;
	}

	if(resolve_(didDocument, (char *)server_did) != DID_RESOLVE_OK){
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_NO_DID_DOCUMENT_RESOLVED);
		return MSG_PROCESS_ERROR;
	}

	if((pubkey = BIO_new_mem_buf(didDocument->authMethod.pk_pem.p, -1)) == NULL){
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return MSG_PROCESS_ERROR;
	}

	if((s->session->peer_did_pubkey = PEM_read_bio_PUBKEY(pubkey, NULL, NULL, NULL)) == NULL ){
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return MSG_PROCESS_ERROR;
	}

	/* Save the current hash state for when we receive the DidVerify */
	if (!ssl_handshake_hash(s, s->did_verify_hash, sizeof(s->did_verify_hash),
			&s->did_verify_hash_len)) {
		/* SSLfatal() already called */;
		return MSG_PROCESS_ERROR;
	}

	return MSG_PROCESS_CONTINUE_READING;
}


/*
 * Check a did can be used for client authentication. Currently check
 * did exists.
 */
static int tls_check_client_did(SSL *s) {
	/* If no suitable signature algorithm can't use did */
	if (!tls_choose_did_sigalg(s, 0) || s->s3.tmp.sigalg == NULL)
		return 0;

	return 1;
}

WORK_STATE tls_prepare_client_did(SSL *s, WORK_STATE wst){

	if(wst == WORK_MORE_A){
		if(tls_check_client_did(s))
			return WORK_FINISHED_CONTINUE;
	}

	/* Shouldn't ever get here */
	SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
	return WORK_ERROR;
}

int tls_construct_client_did(SSL *s, WPACKET *pkt){

	/* PHA handling could be implemented, check client certificate */

	/* no context available, add 0-length context */
	if (!WPACKET_put_bytes_u8(pkt, 0)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* Did method of client did*/
	if (!WPACKET_put_bytes_u8(pkt, s->did->key->did_method)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* The actual did */
	if (!WPACKET_sub_memcpy_u16(pkt, s->did->key->did, s->did->key->did_len)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	if (SSL_IS_TLS13(s) && SSL_IS_FIRST_HANDSHAKE(s)
			&& (!s->method->ssl3_enc->change_cipher_state(s,
			SSL3_CC_HANDSHAKE | SSL3_CHANGE_CIPHER_CLIENT_WRITE))) {
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

int tls_parse_ctos_supported_did_methods(SSL *s, PACKET *pkt,
		unsigned int context, X509 *x, size_t chainidx) {

#ifndef OPENSSL_NO_TLS1_3
	PACKET supported_did_methods;

	if (!PACKET_as_length_prefixed_1(pkt, &supported_did_methods)
			|| PACKET_remaining(&supported_did_methods) == 0) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
		return 0;
	}

	if (!s->hit
			&& !PACKET_memdup(&supported_did_methods,
					&s->ext.peer_supporteddidmethods,
					&s->ext.peer_supporteddidmethods_len)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

#endif

	return 1;
}

EXT_RETURN tls_construct_stoc_supported_did_methods(SSL *s, WPACKET *pkt,
		unsigned int context, X509 *x, size_t chainidx) {
#ifndef OPENSSL_NO_TLS1_3

	if (s->ext.supporteddidmethods == NULL || s->ext.supporteddidmethods_len == 0)
		return EXT_RETURN_NOT_SENT;

	uint8_t *didmethods;
	size_t didmethodslen;

	s->s3.did_sent = 0;

	if(s->shared_didmethods != NULL){
		didmethods = s->shared_didmethods;
		didmethodslen = s->shared_didmethodslen;
	} else {
		didmethods = s->ext.supporteddidmethods;
		didmethodslen = s->ext.supporteddidmethods_len;
	}

	if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_supported_did_methods)
	/* Sub-packet for sig-algs extension */
	|| !WPACKET_start_sub_packet_u16(pkt)
	/* Sub-packet for the actual list */
	|| !WPACKET_sub_memcpy_u8(pkt, didmethods, didmethodslen)
			|| !WPACKET_close(pkt)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return EXT_RETURN_FAIL;
	}
	return EXT_RETURN_SENT;
#else
	return EXT_RETURN_NOT_SENT;
#endif
}

int tls_construct_did_request(SSL *s, WPACKET *pkt) {

	/* Request context must be 0-length, unless used for PHA */
	if (!WPACKET_put_bytes_u8(pkt, 0)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	if (!tls_construct_extensions(s, pkt, SSL_EXT_TLS1_3_DID_REQUEST, NULL,
			0)) {
		/* SSLfatal() already called */
		return 0;
	}

	/* We don't need s->didreqs_sent here, since it is used with SSL_VERIFY_CLIENT_ONCE */
	s->s3.tmp.did_request = 1;

	return 1;
}

int tls_construct_server_did(SSL *s, WPACKET *pkt) {

	DID_PKEY *dpk = s->s3.tmp.did;

	if (dpk == NULL) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* 0-length context for server Did message */
	if (SSL_IS_TLS13(s) && !WPACKET_put_bytes_u8(pkt, 0)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* 1 byte reserved for the did method of server did*/
	if (!WPACKET_put_bytes_u8(pkt, dpk->did_method)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	/* contains the actual did */
	if (!WPACKET_sub_memcpy_u16(pkt, dpk->did, dpk->did_len)) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return 0;
	}

	return 1;
}


MSG_PROCESS_RETURN tls_process_client_did(SSL *s, PACKET *pkt){

	PACKET context;
	did_document_ *didDocument = NULL;
	unsigned int did_len, method;
	unsigned char client_did[100];
	BIO *pubkey;


	didDocument = calloc(1, sizeof(did_document_));
	if (didDocument == NULL) {
		SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
		return MSG_PROCESS_ERROR;
	}

	did_document_init(didDocument);

	/*
	 * To get this far we must have read encrypted data from the client. We no
	 * longer tolerate unencrypted alerts. This value is ignored if less than
	 * TLSv1.3
	 */
	s->statem.enc_read_state = ENC_READ_STATE_VALID;

	if ((!PACKET_get_length_prefixed_1(pkt, &context)
					|| (s->pha_context == NULL
							&& PACKET_remaining(&context) != 0)
					|| (s->pha_context != NULL
							&& !PACKET_equal(&context, s->pha_context,
									s->pha_context_len)))) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_INVALID_CONTEXT);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_get_1(pkt, &method)) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_TOO_SHORT);
		return MSG_PROCESS_ERROR;
	}

	if (!PACKET_get_net_2(pkt, &did_len)
			|| !PACKET_copy_bytes(pkt, client_did, did_len)
			|| PACKET_remaining(pkt) != 0) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
		return MSG_PROCESS_ERROR;
	}

	if (resolve_(didDocument, (char*) client_did) != DID_RESOLVE_OK){
		SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_NO_DID_DOCUMENT_RESOLVED);
		return MSG_PROCESS_ERROR;
	}

	if ((pubkey = BIO_new_mem_buf(didDocument->authMethod.pk_pem.p, -1)) == NULL) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
		return MSG_PROCESS_ERROR;
	}

	if ((s->session->peer_did_pubkey = PEM_read_bio_PUBKEY(pubkey, NULL, NULL,
	NULL)) == NULL) {
		SSLfatal(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
		return MSG_PROCESS_ERROR;
	}

	/*
	 * Freeze the handshake buffer
	 */
	if (!ssl3_digest_cached_records(s, 1)) {
		/* SSLfatal() already called */
		return MSG_PROCESS_ERROR;
	}

	/* Save the current hash state for when we receive the DidVerify */
	if (!ssl_handshake_hash(s, s->did_verify_hash, sizeof(s->did_verify_hash),
			&s->did_verify_hash_len)) {
		/* SSLfatal() already called */;
		return MSG_PROCESS_ERROR;
	}

	return MSG_PROCESS_CONTINUE_READING;
}

