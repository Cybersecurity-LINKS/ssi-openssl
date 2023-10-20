Here's a list of the major files that have been added/modified for the SSI version of OpenSSL.

## `Include`

#### `crypto`

- `did.h`: defines the `DID_DOC` structure to store the fields of a DID document. 
- `vc.h`: `VC` contains the fields of a VC, while a `VC_ISSUER` is identified by the name of its public key and the public key itself. 
- `evp_ssi.h`: defines `EVP_VC` and `EVP_DID` structures

#### `openssl`

- `core_dispatch.h`: defines `OP_DID` and `OP_VC` operations.
    - `OP_DID` offers the functionalities to **create**, **resolve**, **update** and **delete** a DID.
    - `OP_VC` allows to **create**, **serialize**, **deserialize** and **verify** a VC.
- `core_names.h`: defines params for the `OP_DID` and `OP_VC` operations.
- `evp_ssi.h`: declares `EVP_DID` and `EVP_VC` functions

## `Crypto`

- `evp_local_ssi.h`: definition of `EVP_VC_CTX` and `EVP_DID_CTX` structures.
- `did_lib.c` and `did_meth.c`: definition of `EVP_DID` functions
- `vc_lib.c` and `vc_meth.c`: definition of `EVP_VC` functions

## `ssl`

- `ssl_local.h`: defines `ssi_params_st`, `did_pkey_st` and `did_st` structures. The first one contains the fields for the ssi params extension, the second and third ones have the same functionality of `cert_pkey_st` and `cert_st` but for DID documents.

- `ssl_local_did.h` and `did.c`: contain respectively the declaration and definition of functions to fill SSL_CTX and SSL structures with DID related content.  
- `ssl_local_vc.h` and `vc.c`:  contain respectively the declaration and definition of functions to fill SSL_CTX and SSL structures with VC related content. 

#### `statem`

- `statem_local_ssi.h` and `statem_local_ssi.c`:
contains respectively declaration and definition of functions to construct and process the new extension/messages.

- `statem_server.c` and `statem_client.c`: contain modifications to their write and read state machines to construct and process the new messages.

## `Apps`

- `apps/s_client.c` and `apps/s_server.c` : present five new extensions:
    - `-did`: endpoint's DID
    - `-did_key`: file containing the endpoint's DID private key.
    - `-did_methods`: list of DID methods supported by the client.
    - `-vc`: expects a file that contains the endpoint's VC.
    - `-VCIfile`: expects a file containing the list of VC issuers trusted by the client. 
    
    If `-did_methods` option is present the endpoint will send ssi parameters extension with authentication mode set to DID. If in addition to the latter `-VCIfile` is present the endpoint will send ssi parameters extension with authentication mode set to VC. On client side if none of the two options are present but `-did` option and (optionally)`-vc` are present it will send the ssi parameters extension with authentication mode set to 0 and a 0 length-value of did methods.

