#ifndef OSSL_CRYPTO_SSI_H
# define OSSL_CRYPTO_EVP_SSI_H
# pragma once

# include <openssl/core_dispatch.h>
# include <openssl/types.h>

/* DID */

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


struct evp_vc_st {
    OSSL_PROVIDER *prov;
    int name_id;
    char *type_name;
    const char *description;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

	OSSL_FUNC_vc_newctx_fn *newctx;
    OSSL_FUNC_vc_create_fn *create;
	OSSL_FUNC_vc_verify_fn *verify;
	OSSL_FUNC_vc_serialize_fn *serialize;
	OSSL_FUNC_vc_deserialize_fn *deserialize;
	OSSL_FUNC_vc_freectx_fn *freectx;
	OSSL_FUNC_vc_set_ctx_params_fn *set_ctx_params;
	OSSL_FUNC_vc_get_ctx_params_fn *get_ctx_params;
} /* SSI_VC */;

//void a (void);

#endif
