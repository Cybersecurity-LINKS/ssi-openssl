#ifndef OPENSSL_SSI_H
# define OPENSSL_SSI_H

# pragma once

# include <openssl/core_dispatch.h>
# include "ssi.h"
# include <openssl/types.h>

# define DID_OTT "OTT"
# define DID_OK 1
# define DID_NOT_FOUD 0
# define DID_REVOKED -1
# define DID_INTERNAL_ERROR -2

# define VC_OK 1
# define VC_ERROR -1

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


SSI_VC_CTX *SSI_VC_CTX_new(SSI_VC *vc);
void SSI_VC_CTX_free(SSI_VC_CTX *ctx);
SSI_VC *SSI_VC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm, const char *properties);
char *SSI_VC_create(SSI_VC_CTX *ctx, EVP_PKEY *pkey, OSSL_PARAM params[]);
int SSI_VC_verify(SSI_VC_CTX *ctx, EVP_PKEY *pkey, OSSL_PARAM params[]);
int SSI_VC_deserialize(SSI_VC_CTX *ctx, unsigned char *vc_stream, OSSL_PARAM params[]);
unsigned char *SSI_VC_serialize(SSI_VC_CTX *ctx, OSSL_PARAM params[]);
int SSI_VC_CTX_get_params(SSI_VC_CTX *ctx, OSSL_PARAM params[]);
int SSI_VC_CTX_set_params(SSI_VC_CTX *ctx, OSSL_PARAM params[]);

#endif
