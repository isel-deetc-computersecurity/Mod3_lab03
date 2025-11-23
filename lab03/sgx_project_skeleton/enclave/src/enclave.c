#include "enclave_t.h"
#include "enclave.h"
#include <sgx_tseal.h>

void ecall_get_rand(unsigned char * data_sealed){

    int buf_size = 4; //tamanho em bytes do valor a ser gerado 
    unsigned char buf[buf_size];    // Buffer para buf_size bytes aleatório

    uint_32_t old_prime;
    uint_32_t data_size = status = sgx_calc_sealed_data_size(0,sizeof(uint32_t));
    sgx_status_t status = data_unseal(data_sealed, &old_prime, &data_size);

   // Generate the new random prime
	int p, new_prime;
	do {
		// Generate a random prime
		p = 0;
		do {
			sgx_read_rand(buf,buf_size);
            new_prime = (int)_[0] | (int)buf[1] << 8 | (int)buf[2] << 16 | (int)buf[3] << 24;
			p = is_prime( new_prime );
		} while( p != 1 );

	} while( new_prime == old_prime );

    sgx_sealed_data_t sealed_data;
    status = data_seal(&sealed_data, new_prime,sizeof(uint32_t));

}

int ecall_get_size(){

    int status = 0;
    status = sgx_calc_sealed_data_size(0,4);
    return status;
}

sgx_status_t data_unseal(unsigned char *data_sealed,uint_32_t *p_decrypted_text, uint_32_t *p_decrypted_text_length){

    sgx_status_t sgx_status;
    sgx_status = sgx_unseal_data((sgx_sealed_data_t *) data_sealed,NULL,NULL, p_decrypted_text,p_decrypted_text_length);
    
    return sgx_status;
}

sgx_status_t data_seal(sgx_sealed_data_t * p_sealed_data, uint8_t p_text2encrypt, uint32_t text2encrypt_length){

    
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0,text2encrypt_length);

    sgx_status_t sgx_status;
    sgx_status = sgx_seal_data(NULL,0,text2encrypt_length, p_text2encrypt, sealed_data_size, p_sealed_data);

    return status;
}


