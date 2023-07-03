#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include "internal/provider.h"
#include "internal/core.h"
#include "crypto/evp.h"
#include "evp_local.h"
#include "crypto/evp_ssi.h"

static int evp_vc_up_ref(void *vvc)
{
    EVP_VC *vc = (EVP_VC *)vvc;
    int ref = 0;

    CRYPTO_UP_REF(&vc->refcnt, &ref, vc->lock);
    return 1;
}

static void evp_vc_free(void *vvc)
{
	EVP_VC *vc = (EVP_VC *)vvc;
	int ref = 0;

	if (vc == NULL)
		return;

	CRYPTO_DOWN_REF(&vc->refcnt, &ref, vc->lock);
	if (ref > 0)
		return;
	OPENSSL_free(vc->type_name);
	ossl_provider_free(vc->prov);
	CRYPTO_THREAD_lock_free(vc->lock);
	OPENSSL_free(vc);
}

static void *evp_vc_new(void)
{
    EVP_VC *vc = NULL;

    if ((vc = OPENSSL_zalloc(sizeof(*vc))) == NULL
        || (vc->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        evp_vc_free(vc);
        return NULL;
    }
    vc->refcnt = 1;
    return vc;
}


static void *evp_vc_from_algorithm(int name_id,
                                    const OSSL_ALGORITHM *algodef,
                                    OSSL_PROVIDER *prov)
{
	const OSSL_DISPATCH *fns = algodef->implementation;
    EVP_VC *vc = NULL;
    int fnvccnt = 0, fnctxcnt = 0;

    if ((vc = evp_vc_new()) == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    vc->name_id = name_id;
    if ((vc->type_name = ossl_algorithm_get1_first_name(algodef)) == NULL) {
        evp_vc_free(vc);
        return NULL;
    }
    vc->description = algodef->algorithm_description;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_VC_NEWCTX:
            if (vc->newctx != NULL)
                break;
            vc->newctx = OSSL_FUNC_vc_newctx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_VC_FREECTX:
            if (vc->freectx != NULL)
                break;
            vc->freectx = OSSL_FUNC_vc_freectx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_VC_CREATE:
            if (vc->create != NULL)
                break;
            vc->create = OSSL_FUNC_vc_create(fns);
            fnvccnt++;
            break;
        case OSSL_FUNC_VC_VERIFY:
            if (vc->verify != NULL)
                break;
            vc->verify = OSSL_FUNC_vc_verify(fns);
            fnvccnt++;
            break;
        case OSSL_FUNC_VC_SERIALIZE:
            if (vc->serialize != NULL)
                break;
            vc->serialize = OSSL_FUNC_vc_serialize(fns);
            fnvccnt++;
            break;
        case OSSL_FUNC_VC_DESERIALIZE:
            if (vc->deserialize != NULL)
                break;
            vc->deserialize =
                OSSL_FUNC_vc_deserialize(fns);
            fnvccnt++;
            break;
        case OSSL_FUNC_VC_GET_CTX_PARAMS:
            if (vc->get_ctx_params != NULL)
                break;
            vc->get_ctx_params = OSSL_FUNC_vc_get_ctx_params(fns);
            break;
        case OSSL_FUNC_VC_SET_CTX_PARAMS:
            if (vc->set_ctx_params != NULL)
                break;
            vc->set_ctx_params = OSSL_FUNC_vc_set_ctx_params(fns);
            break;
        }
    }
    if (fnvccnt < 1
        || fnctxcnt != 2) {
        /*
         * In order to be a consistent set of functions we must have at least
         * a complete set of "vc" functions, and a complete set of context
         * management functions, as well as the size function.
         */
        evp_vc_free(vc);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }
    vc->prov = prov;
    if (prov != NULL)
        ossl_provider_up_ref(prov);

    return vc;
}

EVP_VC *EVP_VC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm, const char *properties)
{
	EVP_VC *vc =
	        evp_generic_fetch(libctx, OSSL_OP_VC, algorithm, properties,
	                          evp_vc_from_algorithm, evp_vc_up_ref, evp_vc_free);

	    return vc;
}

int EVP_VC_up_ref(EVP_VC *vc)
{
	return evp_vc_up_ref(vc);
}

void EVP_VC_free(EVP_VC *vc)
{
	return evp_vc_free(vc);
}
