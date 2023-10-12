/*
 * did.h
 *
 *  Created on: Jun 8, 2022
 *      Author: leonardo
 */

#ifndef SSL_STATEM_STATEM_LOCAL_DID_H_
#define SSL_STATEM_STATEM_LOCAL_DID_H_

#include "../ssl_local.h"
#include "statem_local.h"

/********************************************************
 **************** GENERAL METHODS ***********************
 ********************************************************/

/* For the other extensions this function is defined as static in extensions.c */
int init_ssi_params(SSL *s, unsigned int context);

__owur int tls_construct_did_verify(SSL *s, WPACKET *pkt);

__owur MSG_PROCESS_RETURN tls_process_did_verify(SSL *s, PACKET *pkt);

/********************************************************
 **************** CLIENT METHODS  ***********************
 ********************************************************/

/*************************** SSI methods ***************************/

EXT_RETURN tls_construct_ctos_ssi_params(SSL *s, WPACKET *pkt, unsigned int context, X509 *x, size_t chainidx);

int tls_parse_stoc_ssi_params(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
        size_t chainidx);

__owur MSG_PROCESS_RETURN tls_process_ssi_request(SSL *s, PACKET *pkt);

__owur WORK_STATE tls_prepare_client_ssi(SSL *s, WORK_STATE wst);

/*************************** VC methods ***************************/

__owur MSG_PROCESS_RETURN tls_process_server_vc(SSL *s, PACKET *pkt);

__owur WORK_STATE tls_post_process_server_vc(SSL *s, WORK_STATE wst);

__owur int tls_construct_client_vc(SSL *s, WPACKET *pkt);

/*************************** DID methods ***************************/

__owur MSG_PROCESS_RETURN tls_process_server_did(SSL *s, PACKET *pkt);

__owur int tls_construct_client_did(SSL *s, WPACKET *pkt);

/********************************************************
 **************** SERVER METHODS  ***********************
 ********************************************************/

/*************************** SSI methods ***************************/

int tls_parse_ctos_ssi_params(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx);

EXT_RETURN tls_construct_stoc_ssi_params(SSL *s, WPACKET *pkt, unsigned int context,
        X509 *x, size_t chainidx);

/*************************** VC methods ***************************/

__owur int tls_construct_ssi_request(SSL *s, WPACKET *pkt);

__owur int tls_construct_server_vc(SSL *s, WPACKET *pkt);

__owur MSG_PROCESS_RETURN tls_process_client_vc(SSL *s, PACKET *pkt);

/*************************** DID methods ***************************/

__owur int tls_construct_server_did(SSL *s, WPACKET *pkt);

__owur MSG_PROCESS_RETURN tls_process_client_did(SSL *s, PACKET *pkt);

#endif /* SSL_STATEM_STATEM_LOCAL_DID_H_ */
