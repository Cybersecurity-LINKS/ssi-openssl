#ifndef OSSL_CRYPTO_SSI_H
# define OSSL_CRYPTO_SSI_H
# pragma once

# include <openssl/core_dispatch.h>
# include "../openssl/ssi.h"
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

/* VC */

struct vc_ctx_st {
	OSSL_LIB_CTX *libctx;
	char *methodtype;

	/* Method associated with this operation */
	OSSL_FUNC_vc_create_fn *vc_create;
	OSSL_FUNC_vc_verify_fn *vc_verify;
	OSSL_FUNC_vc_serialize_fn *vc_serialize;
	OSSL_FUNC_vc_deserialize_fn *vc_deserialize;
	OSSL_PROVIDER *prov;
};

typedef struct vc_buf {
    unsigned char *p;
    size_t len;
} vc_buf;

typedef struct csubj {
    vc_buf id;
} csubj;

typedef struct proof {
    vc_buf type;
    vc_buf created;
    vc_buf purpose;
    vc_buf verificationMethod;
    vc_buf signature;
} proof;


struct vc_st {
	vc_buf atContext;
	vc_buf id;
	vc_buf type;
	vc_buf issuer;
	vc_buf issuanceDate;
	vc_buf credentialSubject;
	proof proof;
};

//void a (void);

#endif
