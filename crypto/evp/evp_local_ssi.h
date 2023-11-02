/*
 * Copyright 2023 Fondazione Links.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.	
 *
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
