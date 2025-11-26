#ifndef _ENCLAVE__h
#define _ENCLAVE_H_

#include "sgx_trts.h"
#include <sgx_tseal.h>
#include <stdint.h>

int is_prime( int n );
sgx_status_t data_unseal(unsigned char *data_sealed,uint32_t *p_decrypted_text, uint32_t *p_decrypted_text_length);
sgx_status_t data_seal(sgx_sealed_data_t * p_sealed_data, uint8_t *p_text2encrypt, uint32_t text2encrypt_length);
#endif