/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


#ifndef CRYPTO_EVP_EVP_LOCAL_SSI_H_
#define CRYPTO_EVP_EVP_LOCAL_SSI_H_

#include <openssl/types.h>

struct evp_vc_ctx_st {
	EVP_VC *meth;               /* Method structure */
    /*
     * Opaque ctx returned from a providers VC algorithm implementation
     * OSSL_FUNC_vc_newctx()
     */
    void *algctx;
} /* EVP_VC_CTX */;

struct evp_did_ctx_st {
	EVP_DID *meth;               /* Method structure */
    /*
     * Opaque ctx returned from a providers DID algorithm implementation
     * OSSL_FUNC_did_newctx()
     */
    void *algctx;
} /* EVP_DID_CTX */;

#endif /* CRYPTO_EVP_EVP_LOCAL_SSI_H_ */
