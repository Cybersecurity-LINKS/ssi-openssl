/*
 * did.c
 *
 *  Created on: Oct 12, 2022
 *      Author: leonardo
 */

#include <openssl/ssl.h>
#include <ssl/ssl_local_did.h>
#include <ctype.h>

/* Default supported did methods scheme*/
/* static const uint8_t supported_did_methods_default[] = { TLSEXT_DID_METHOD_ott,
TLSEXT_DID_METHOD_btc }; */

static const DIDMETHOD_LOOKUP didmethods_lookup_tbl[] = {
		{ "ott", TLSEXT_DID_METHOD_ott },
		{ "btc", TLSEXT_DID_METHOD_btc },
		{ "eth", TLSEXT_DID_METHOD_eth }
};

/************************************************
 **************** METHODS ***********************
 ************************************************/

/* Declared in openssl/include/openssl/ssl.h */
int SSL_CTX_set_did_methods(SSL_CTX *ctx, const char *did_methods){

	/*if(did_methods == NULL){
		ctx->ext.supporteddidmethods = NULL;
		ctx->ext.supporteddidmethods_len = 0;
		return 1;
	}*/

	size_t len, i, j = 0, k, t = 0, size = 0;
	char method[10];
	uint8_t supported_did_methods[256];

	len = strlen(did_methods);
	if (len == 0 || len >= 65535)
		return 0;

	for (i = 0; i <= len; ++i) {
		if (i == len || did_methods[i] == ',') {
			method[j] = '\0';
			for (k = 0; k < OSSL_NELEM(didmethods_lookup_tbl); k++){
				if(strcmp(method, didmethods_lookup_tbl[k].name) == 0){
					supported_did_methods[t++] = didmethods_lookup_tbl[k].didmethod;
					size++;
					break;
				}
			}
			j = 0;
		} else {
			method[j++] = did_methods[i];
		}
	}

	if(!size)
		return 0;

	ctx->ext.supporteddidmethods = OPENSSL_malloc(sizeof(uint8_t) * size);

	if (ctx->ext.supporteddidmethods == NULL) {
		ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	memcpy(ctx->ext.supporteddidmethods, supported_did_methods,
				size * sizeof(uint8_t));
	ctx->ext.supporteddidmethods_len = size;

	return 1;
}

/* Load the supported did methods in the SSL_CTX struct which will be
 * then assigned to the SSL struct */
/* int ssl_load_supported_did_methods(SSL_CTX *ctx) {

	size_t supporteddidmethods_len = OSSL_NELEM(supported_did_methods_default);

	if(supporteddidmethods_len == 0){
		ctx->ext.supporteddidmethods = NULL;
		ctx->ext.supporteddidmethods_len = 0;
		return 1;
	}

	uint8_t supporteddidmethods[supporteddidmethods_len];

	ctx->ext.supporteddidmethods = OPENSSL_malloc(
			sizeof(uint8_t) * supporteddidmethods_len);

	if (ctx->ext.supporteddidmethods == NULL) {
		ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	memcpy(ctx->ext.supporteddidmethods, supported_did_methods_default,
			supporteddidmethods_len * sizeof(supporteddidmethods[0]));
	ctx->ext.supporteddidmethods_len = supporteddidmethods_len;

	return 1;
} */

static int tls13_shared_didmethods(SSL *s, uint8_t **shmethods,
                                   const uint8_t *pref, size_t preflen,
                                   const uint8_t *allow, size_t allowlen){

	const uint8_t *ptmp, *atmp;
	size_t i, j, nmatch = 0;

	for (i = 0, ptmp = pref; i < preflen; i++, ptmp++) {
		for (j = 0, atmp = allow; j < allowlen; j++, atmp++) {
			if(*ptmp == *atmp) {
				nmatch++;
				if(shmethods){
					*shmethods++ = ptmp;
				}
				break;
			}
		}
	}
	return nmatch;
}

static int tls13_set_shared_didmethods(SSL *s){

	uint8_t **shmethods = NULL;
	size_t nmatch, preflen, allowlen;
	const uint8_t *pref, *allow;

	OPENSSL_free(s->shared_didmethods);
	s->shared_didmethods = NULL;
	s->shared_didmethodslen = 0;

	pref = s->ext.peer_supporteddidmethods;
	preflen = s->ext.peer_supporteddidmethods_len;
	allow = s->ext.supporteddidmethods;
	allowlen = s->ext.supporteddidmethods_len;

	nmatch = tls13_shared_didmethods(s, NULL, pref, preflen, allow, allowlen);
	if(nmatch){
		if ((shmethods = OPENSSL_malloc(nmatch * sizeof(*shmethods))) == NULL) {
			ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
			return 0;
		}
		nmatch = tls13_shared_didmethods(s, shmethods, pref, preflen, allow, allowlen);
	} else {
		shmethods = NULL;
		return 0;
	}
	s->shared_didmethods = *shmethods;
	s->shared_didmethodslen = nmatch;
	return 1;
}

/* Check if our did is compatible with one of the did methods sent by the peer */
static int is_did_method_supported(SSL *s) {

	size_t i, j;
	const DIDMETHOD_LOOKUP *lu;
	/*DIDMETHOD_LOOKUP *cache = OPENSSL_malloc(
			sizeof(*lu) * OSSL_NELEM(didmethods_lookup_tbl));

	if (cache == NULL)
		goto err;*/

	for (i = 0; i < s->ext.peer_supporteddidmethods_len; i++) {
		for (j = 0, lu = didmethods_lookup_tbl;
				j < OSSL_NELEM(didmethods_lookup_tbl); j++, lu++) {
			if (s->ext.peer_supporteddidmethods[i] == lu->didmethod)
				if (s->did->key->did_method == s->ext.peer_supporteddidmethods[i])
						return 1;
				/*cache[k++] = *lu;*/
		}
	}

	/*for (i = 0; i < k; i++)
		if (s->did->key->did_method == cache[i].didmethod)
			return 1;
err:
	OPENSSL_free(cache);*/
	return 0;
}

int tls13_set_server_did_methods(SSL *s) {

	if (s->ext.peer_supporteddidmethods == NULL) { /* the client did not send the supported did methods extension */
		s->auth_method = CERTIFICATE_AUTHN;
		return 1;
	/* The server does not support did methods or its did is
	 * not included in the list of did methods sent by the client */
	} else if (s->ext.supporteddidmethods == NULL
			|| !tls13_set_shared_didmethods(s)
			|| !is_did_method_supported(s)) {
		SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_NO_SHARED_DID_METHODS);
		return 0;
	} else {
		s->auth_method = DID_AUTHN;
		return 1;
	}
}

/* Returns true if did document and private key for 'idx' are present */
int ssl_has_did(const SSL *s, int idx) {
	if (idx < 0 || idx >= SSL_PKEY_NUM)
		return 0;
	return s->did->pkeys[idx].did != NULL
			&& s->did->pkeys[idx].did_len != 0
			&& s->did->pkeys[idx].did_method != 0
			&& s->did->pkeys[idx].privatekey != NULL;
}

static int check_did_usable(SSL *s, const SIGALG_LOOKUP *sig, EVP_PKEY *pkey) {

	int supported;
	const char *mdname = NULL;

	/*
	 * If the given EVP_PKEY cannot support signing with this digest,
	 * the answer is simply 'no'.
	 */
	if (sig->hash != NID_undef)
		mdname = OBJ_nid2sn(sig->hash);
	supported = EVP_PKEY_digestsign_supports_digest(pkey, s->ctx->libctx,
			mdname, s->ctx->propq);
	if (supported <= 0)
		return 0;

	return 1;
}

static int has_usable_did(SSL *s, const SIGALG_LOOKUP *sig, int idx) {

	/* TLS 1.2 callers can override sig->sig_idx, but not TLS 1.3 callers. */
	if (idx == -1)
		idx = sig->sig_idx;

	if (!ssl_has_did(s, idx))
		return 0;

	return check_did_usable(s, sig, s->did->pkeys[idx].privatekey);

}

/*
 * Check if key is large enough to generate RSA-PSS signature.
 *
 * The key must be greater than or equal to 2 * hash length + 2.
 * SHA512 has a hash length of 64 bytes, which is incompatible
 * with a 128 byte (1024 bit) key.
 */
#define RSA_PSS_MINIMUM_KEY_SIZE(md) (2 * EVP_MD_get_size(md) + 2)
static int rsa_pss_check_min_key_size(SSL_CTX *ctx, const EVP_PKEY *pkey,
		const SIGALG_LOOKUP *lu) {
	const EVP_MD *md;

	if (pkey == NULL)
		return 0;
	if (!tls1_lookup_md(ctx, lu, &md) || md == NULL)
		return 0;
	if (EVP_PKEY_get_size(pkey) < RSA_PSS_MINIMUM_KEY_SIZE(md))
		return 0;
	return 1;
}

static const SIGALG_LOOKUP* find_did_sig_alg(SSL *s) { /* I don't add X_509 and EVP_KEY parameters since they are only used to verify the certificate chain */

	const SIGALG_LOOKUP *lu = NULL;
	size_t i;
	int curve = -1;
	EVP_PKEY *tmppkey;

	/* Look for a shared sigalgs matching possible certificates */
	for (i = 0; i < s->shared_sigalgslen; i++) {
		lu = s->shared_sigalgs[i];

		/* Skip SHA1, SHA224, DSA and RSA if not PSS */
		if (lu->hash == NID_sha1 || lu->hash == NID_sha224
				|| lu->sig == EVP_PKEY_DSA || lu->sig == EVP_PKEY_RSA)
			continue;
		if (!tls1_lookup_md(s->ctx, lu, NULL))
			continue;
		/* Check that we have a did */
		if (!has_usable_did(s, lu, -1))
			continue;

		tmppkey = s->did->pkeys[lu->sig_idx].privatekey;

		if (lu->sig == EVP_PKEY_EC) {
			if (curve == -1)
				curve = ssl_get_EC_curve_nid(tmppkey);
			if (lu->curve != NID_undef && curve != lu->curve)
				continue;
		} else if (lu->sig == EVP_PKEY_RSA_PSS) {
			/* validate that key is large enough for the signature algorithm */
			if (!rsa_pss_check_min_key_size(s->ctx, tmppkey, lu))
				continue;
		}
		break;
	}

	if (i == s->shared_sigalgslen)
		return NULL;

	return lu;
}

int tls_choose_did_sigalg(SSL *s, int fatalerrs) {

	const SIGALG_LOOKUP *lu = NULL;
	int sig_idx = -1;

	s->s3.tmp.did = NULL;
	s->s3.tmp.sigalg = NULL;

	lu = find_did_sig_alg(s);
	if (lu == NULL) {
		if (!fatalerrs)
			return 1;
		SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE,
				SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM);
		return 0;
	}

	if (sig_idx == -1)
		sig_idx = lu->sig_idx;

	s->s3.tmp.did = &s->did->pkeys[sig_idx];
	s->did->key = s->s3.tmp.did;
	s->s3.tmp.sigalg = lu;
	return 1;
}

/*Create and return a new DID object*/

DID* ssl_did_new(void) {

	DID *ret = OPENSSL_zalloc(sizeof(*ret));

	if (ret == NULL) {
		ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	ret->key = &(ret->pkeys[SSL_PKEY_RSA]);

	/*ret->references = 1;
	ret->lock = CRYPTO_THREAD_lock_new();
	if (ret->lock == NULL) {
		ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
		OPENSSL_free(ret);
		return NULL;
	}*/

	return ret;
}

/* Duplicates the content of a DID object, used to initialize an SSL structure */

DID* ssl_did_dup(DID *did) {

	DID *ret = OPENSSL_zalloc(sizeof(*ret));
	int i;

	if (ret == NULL) {
		ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	/*ret->references = 1;*/
	ret->key = &ret->pkeys[did->key - did->pkeys];
	/*ret->lock = CRYPTO_THREAD_lock_new();
	if (ret->lock == NULL) {
		ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
		OPENSSL_free(ret);
		return NULL;
	}*/

	for (i = 0; i < SSL_PKEY_NUM; i++) {
		DID_PKEY *dpk = did->pkeys + i;
		DID_PKEY *rpk = ret->pkeys + i;

		if (dpk->did != NULL) {
			/*rpk->did = malloc(dpk->did_len);
			strcpy(rpk->did, dpk->did);*/
			rpk->did = OPENSSL_malloc(dpk->did_len);
			memcpy(rpk->did, dpk->did, dpk->did_len);
			/*rpk->did = dpk->did;*/
			/*DID_up_ref(rpk->something);*/
		}

		if (dpk->did_len != 0) {
			rpk->did_len = dpk->did_len;
		}

		if (dpk->did_method != 0) {
			rpk->did_method = dpk->did_method;
		}

		if (dpk->privatekey != NULL) {
			rpk->privatekey = dpk->privatekey;
			EVP_PKEY_up_ref(dpk->privatekey);
		}
	}
	return ret;
}

/*
 * Should we send a DidRequest message?
 *
 * Valid return values are:
 *   1: Yes
 *   0: No
 */

int send_did_request(SSL *s) {
	if (
	/* don't request did unless asked for it: */
	s->verify_mode & SSL_VERIFY_PEER
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

static int did_method_lookup_by_name(char *method, int *did_method) {

	size_t i;

	for (i = 0; i < OSSL_NELEM(didmethods_lookup_tbl); i++) {
		if (strcmp(method, didmethods_lookup_tbl[i].name) == 0) {
			*did_method = didmethods_lookup_tbl[i].didmethod;
			return 1;
		}
	}

	return 0;
}

/* Check if the did syntax is valid */
static int is_did_valid (char *did, int *did_method){

	char *token;
	token = strtok(did, ":");

	size_t i = 0, j;

	while(token != NULL){
		switch(i) {
		case 0:
			if(strcmp(token, "did") != 0){
				ERR_raise(ERR_LIB_SSL, SSL_R_INVALID_DID);
				return 0;
			}
			break;
		case 1:
			if(!did_method_lookup_by_name(token, did_method)){
				ERR_raise(ERR_LIB_SSL, SSL_R_DID_METHOD_NOT_SUPPORTED);
				return 0;
			}
			break;
		case 2:
			for(j = 0; j < strlen(token); j++){
				if(!isalnum(token[j])){
					ERR_raise(ERR_LIB_SSL, SSL_R_INVALID_DID);
					return 0;
				}
			}
			break;
		}
		token = strtok(NULL, ":");
		i++;
	}
	return 1;
}


static int ssl_set_did_pkey(DID *d, EVP_PKEY *pkey, char *did) {

	size_t i;
	int did_method;

	/* "cert" in the function below means key type */
	if (ssl_cert_lookup_by_pkey(pkey, &i) == NULL) {
		ERR_raise(ERR_LIB_SSL, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
		return 0;
	}

	if(!is_did_valid(strdup(did), &did_method))
		return 0;

	/*if (d->pkeys[i].did != NULL
	 && !check_private_key(c->pkeys[i].x509, pkey))
	 return 0;*/

	EVP_PKEY_free(d->pkeys[i].privatekey);
	EVP_PKEY_up_ref(pkey);
	d->pkeys[i].privatekey = pkey;
	d->key = &d->pkeys[i];
	d->pkeys[i].did = (unsigned char*) did;
	d->pkeys[i].did_len = strlen(did);
	d->pkeys[i].did_method = did_method;

	return 1;
}

int tls1_process_supported_did_methods(SSL *s) {

	if (!is_did_method_supported(s))
		return 0;

	return 1;
}

/* Defined in openssl/include/openssl/ssl.h */
int SSL_CTX_use_did_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey, char *did) {

	if (pkey == NULL) {
		ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (did == NULL) {
		ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	return ssl_set_did_pkey(ctx->did, pkey, did);
}

/* Declared in openssl/include/openssl/ssl.h */
EVP_PKEY *SSL_get0_peer_did(const SSL *s){

	if ((s == NULL) || (s->session == NULL))
	        return NULL;
	    else
	        return s->session->peer_did_pubkey;
}

/* Declared in openssl/include/openssl/ssl.h */
int is_did_handshake(const SSL *s){

	if(s == NULL)
		return 0;

	return s->s3.did_sent && SSL_IS_TLS13(s);
}

