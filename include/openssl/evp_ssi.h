#ifndef OPENSSL_EVP_SSI_H
# define OPENSSL_EVP_SSI_H

# pragma once

# include <openssl/core_dispatch.h>
# include "evp_ssi.h"
# include <openssl/types.h>

EVP_DID_CTX *EVP_DID_CTX_new(EVP_DID *did);
void EVP_DID_CTX_free(EVP_DID_CTX *ctx);
EVP_DID *EVP_DID_fetch(OSSL_LIB_CTX *libctx, const char *algorithm, const char *properties);
int EVP_DID_up_ref(EVP_DID *did);
void EVP_DID_free(EVP_DID *did);
char *EVP_DID_create(EVP_DID_CTX *ctx, OSSL_PARAM params[]);
int EVP_DID_resolve(EVP_DID_CTX *ctx, char *did, OSSL_PARAM params[]);
char *EVP_DID_update(EVP_DID_CTX *ctx, OSSL_PARAM params[]);
int EVP_DID_revoke(EVP_DID_CTX *ctx);
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
