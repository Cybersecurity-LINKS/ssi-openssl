/*
 * evp_local_ssi.h
 *
 *  Created on: May 24, 2023
 *      Author: pirug
 */

#ifndef CRYPTO_EVP_EVP_LOCAL_SSI_H_
#define CRYPTO_EVP_EVP_LOCAL_SSI_H_

/* VC */

typedef struct vc {
	char *atContext;
	char *id;
	char *type;
	char *issuer;
	char *issuanceDate;
	char *credentialSubject;
	char *proofType;
	char *proofCreated;
	char *proofPurpose;
	char *verificationMethod;
	char *proofValue;
} vc;

struct evp_vc_ctx_st {
     SSI_VC *meth;               /* Method structure */

     vc *vc;
     unsigned char *vc_stream;
    /*
     * Opaque ctx returned from a providers VC algorithm implementation
     * OSSL_FUNC_vc_newctx()
     */
    void *algctx;
} /* SSI_VC_CTX */;

#endif /* CRYPTO_EVP_EVP_LOCAL_SSI_H_ */
