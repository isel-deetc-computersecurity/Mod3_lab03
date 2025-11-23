#ifndef _APP_H_
#define _APP_H_

#define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid;	/* global enclave id */

int is_prime( int n );

#endif /* !_APP_H_ */
