#ifndef OPENSSL_EVP_SSI_H
# define OPENSSL_EVP_SSI_H

# pragma once

# include <openssl/core_dispatch.h>
# include "evp_ssi.h"
# include <openssl/types.h>

# define DID_OTT "OTT"
# define DID_OK 1
# define DID_NOT_FOUD 0
# define DID_REVOKED -1
# define DID_INTERNAL_ERROR -2

DID_CTX* DID_CTX_new(OSSL_PROVIDER * provider);
void DID_CTX_free(DID_CTX *ctx);
DID_DOCUMENT* DID_DOCUMENT_new(void);
void DID_DOCUMENT_free(DID_DOCUMENT* did_doc);
int DID_DOCUMENT_set(DID_DOCUMENT* did_doc, unsigned char* sig1, size_t len1, int type1, unsigned char* sig2, size_t len2, int type2);
int DID_DOCUMENT_set_auth_key(DID_DOCUMENT* did_doc, unsigned char* sig, size_t len, int type);
int DID_DOCUMENT_set_assertion_key(DID_DOCUMENT* did_doc, unsigned char* sig, size_t len, int type);
unsigned char* DID_DOCUMENT_get_auth_key(DID_DOCUMENT* did_doc);
unsigned char* DID_DOCUMENT_get_assertion_key(DID_DOCUMENT* did_doc);
int DID_fetch(OSSL_LIB_CTX *libctx, DID_CTX *ctx, const char *algorithm, const char *properties);
char* DID_create(DID_CTX *ctx, DID_DOCUMENT* did_doc);
int DID_resolve(DID_CTX *ctx, char * did, DID_DOCUMENT* did_doc);
int DID_update(DID_CTX *ctx, DID_DOCUMENT* did_doc, char * did);
int DID_revoke(DID_CTX *ctx, char * did);

EVP_DID_CTX *EVP_DID_CTX_new(EVP_DID *did);
void EVP_DID_CTX_free(EVP_DID_CTX *ctx);
EVP_VC *EVP_DID_fetch(OSSL_LIB_CTX *libctx, const char *algorithm, const char *properties);
int EVP_DID_up_ref(EVP_DID *did);
void EVP_DID_free(EVP_DID *did);
char *EVP_DID_create(EVP_DID_CTX *ctx, OSSL_PARAM params[]);
int EVP_DID_resolve(EVP_DID_CTX *ctx, char *did, char *diddoc, OSSL_PARAM params[]);
char *EVP_DID_update(EVP_DID_CTX *ctx, char *did, OSSL_PARAM params[]);
int EVP_DID_revoke(EVP_DID_CTX *ctx, char *did);
int EVP_DID_CTX_get_params(EVP_DID_CTX *ctx, OSSL_PARAM params[]);
int EVP_DID_CTX_set_params(EVP_DID_CTX *ctx, OSSL_PARAM params[]);


EVP_VC_CTX *EVP_VC_CTX_new(EVP_VC *vc);
void EVP_VC_CTX_free(EVP_VC_CTX *ctx);
EVP_VC *EVP_VC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm, const char *properties);
int EVP_VC_up_ref(EVP_VC *vc);
void EVP_VC_free(EVP_VC *vc);
char *EVP_VC_create(EVP_VC_CTX *ctx, EVP_PKEY *pkey, OSSL_PARAM params[]);
int EVP_VC_verify(EVP_VC_CTX *ctx, EVP_PKEY *pkey, OSSL_PARAM params[]);
int EVP_VC_deserialize(EVP_VC_CTX *ctx, unsigned char *vc_stream, OSSL_PARAM params[]);
unsigned char *EVP_VC_serialize(EVP_VC_CTX *ctx, OSSL_PARAM params[]);
int EVP_VC_CTX_get_params(EVP_VC_CTX *ctx, OSSL_PARAM params[]);
int EVP_VC_CTX_set_params(EVP_VC_CTX *ctx, OSSL_PARAM params[]);

#endif
