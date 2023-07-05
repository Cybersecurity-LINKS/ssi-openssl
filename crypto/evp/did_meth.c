#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include "internal/provider.h"
#include "internal/core.h"
#include "crypto/evp.h"
#include "evp_local.h"
#include "crypto/evp_ssi.h"

static int evp_did_up_ref(void *vdid)
{
    EVP_DID *did = (EVP_DID *)vdid;
    int ref = 0;

    CRYPTO_UP_REF(&did->refcnt, &ref, did->lock);
    return 1;
}

static void evp_did_free(void *vdid)
{
	EVP_DID *did = (EVP_DID *)vdid;
	int ref = 0;

	if (did == NULL)
		return;

	CRYPTO_DOWN_REF(&did->refcnt, &ref, did->lock);
	if (ref > 0)
		return;
	OPENSSL_free(did->type_name);
	ossl_provider_free(did->prov);
	CRYPTO_THREAD_lock_free(did->lock);
	OPENSSL_free(did);
}

static void *evp_did_new(void)
{
    EVP_DID *did = NULL;

    if ((did = OPENSSL_zalloc(sizeof(*did))) == NULL
        || (did->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        evp_did_free(did);
        return NULL;
    }
    did->refcnt = 1;
    return did;
}

static void *evp_did_from_algorithm(int name_id,
                                    const OSSL_ALGORITHM *algodef,
                                    OSSL_PROVIDER *prov)
{
	const OSSL_DISPATCH *fns = algodef->implementation;
    EVP_DID *did = NULL;
    int fndidcnt = 0, fnctxcnt = 0;

    if ((did = evp_did_new()) == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    did->name_id = name_id;
    if ((did->type_name = ossl_algorithm_get1_first_name(algodef)) == NULL) {
        evp_did_free(did);
        return NULL;
    }
    did->description = algodef->algorithm_description;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_DID_NEWCTX:
            if (did->newctx != NULL)
                break;
            did->newctx = OSSL_FUNC_did_newctx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_DID_FREECTX:
            if (did->freectx != NULL)
                break;
            did->freectx = OSSL_FUNC_did_freectx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_DID_CREATE:
            if (did->create != NULL)
                break;
            did->create = OSSL_FUNC_did_create(fns);
            fndidcnt++;
            break;
        case OSSL_FUNC_DID_RESOLVE:
            if (did->resolve != NULL)
                break;
            did->resolve = OSSL_FUNC_did_resolve(fns);
            fndidcnt++;
            break;
        case OSSL_FUNC_DID_UPDATE:
            if (did->update != NULL)
                break;
            did->update = OSSL_FUNC_did_update(fns);
            fndidcnt++;
            break;
        case OSSL_FUNC_DID_REVOKE:
            if (did->revoke != NULL)
                break;
            did->revoke =
                OSSL_FUNC_did_revoke(fns);
            fndidcnt++;
            break;
        case OSSL_FUNC_DID_GET_CTX_PARAMS:
            if (did->get_ctx_params != NULL)
                break;
            did->get_ctx_params = OSSL_FUNC_did_get_ctx_params(fns);
            break;
        case OSSL_FUNC_DID_SET_CTX_PARAMS:
            if (did->set_ctx_params != NULL)
                break;
            did->set_ctx_params = OSSL_FUNC_did_set_ctx_params(fns);
            break;
        }
    }
    if (fndidcnt < 1
        || fnctxcnt != 2) {
        /*
         * In order to be a consistent set of functions we must have at least
         * a complete set of "did" functions, and a complete set of context
         * management functions, as well as the size function.
         */
        evp_did_free(did);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }
    did->prov = prov;
    if (prov != NULL)
        ossl_provider_up_ref(prov);

    return did;
}

EVP_DID *EVP_DID_fetch(OSSL_LIB_CTX *libctx, const char *algorithm, const char *properties)
{
	EVP_DID *did =
	        evp_generic_fetch(libctx, OSSL_OP_DID, algorithm, properties,
	                          evp_did_from_algorithm, evp_did_up_ref, evp_did_free);

	    return did;
}

int EVP_DID_up_ref(EVP_DID *did)
{
	return evp_did_up_ref(did);
}

void EVP_DID_free(EVP_DID *did)
{
	return evp_did_free(did);
}


