#ifndef _APP_H_
#define _APP_H_

#define ENCLAVE_FILENAME "enclave.signed.so"
#define PRIME_FILENAME "prime.txt"

extern sgx_enclave_id_t global_eid;	/* global enclave id */

//int is_prime( int n );
int load_prime( int* prime, const size_t prime_size );
int save_prime( const int* prime, const size_t prime_size );

#endif /* !_APP_H_ */
