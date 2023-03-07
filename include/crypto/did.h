#ifndef OSSL_CRYPTO_DID_H
# define OSSL_CRYPTO_DID_H
# pragma once

# include <openssl/core_dispatch.h>
# include <openssl/did.h>
# include <openssl/types.h>

struct did_ctx_st {
    OSSL_LIB_CTX *libctx;
    char *methodtype;
    /* Method associated with this operation */
    OSSL_FUNC_did_create_fn *didprovider_create;
    OSSL_FUNC_did_resolve_fn *didprovider_resolve;
    OSSL_FUNC_did_update_fn *didprovider_update;
    OSSL_FUNC_did_revoke_fn *didprovider_revoke;
    OSSL_PROVIDER *prov;
};

struct did_document_st {
    //authorization methods
    unsigned char * sig1;
    size_t siglen1;
    int type1;
    //assertion methods    
    unsigned char * sig2;
    size_t siglen2;
    int type2;
};

void a (void);

#endif
