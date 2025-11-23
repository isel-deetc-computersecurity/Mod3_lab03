#include <stdio.h>
#include <math.h>
#include <sgx_urts.h>

#include "app.h"
#include "sgx_utils.h"
#include "enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/* Application entry */
int SGX_CDECL main( int argc, char *argv[] )
{
	(void)(argc);
	(void)(argv);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    ret = sgx_create_enclave(ENCLAVE_FILENAME,SGX_DEBUG_FLAG,NULL,NULL, &global_eid,NULL);

    if ( ret != SGX_SUCCESS){
        print_error_message(ret);

        return -1;
    }

    ret = SGX_ERROR_UNEXPECTED;
    int ecall_return = 0;
    
    //variáveis principais do problemaS
    int buf_size = 4; //tamanho em bytes do valor a ser gerado 
    unsigned char buf[buf_size];    // Buffer para buf_size bytes aleatório
    int p = 0;
    int n = 0;

    int count = 0;

    do{
        ret = ecall_get_rand(global_eid, buf_size, buf);
        if( ret != SGX_SUCCESS){
            print_error_message(ret);
            return -1;
        }

        //* Converter 4 bytes para um inteiro de 32 bits (int) */
        n = (int)buf[0] | (int)buf[1] << 8 | (int)buf[2] << 16 | (int)buf[3] << 24;
        p = is_prime(n);

        printf("%d is%s a prime number.\n", n, (p == 0) ? "n't" : "" );
        count +=1;
    } while( n != 1 && count <= 10);

    /* Destroy the enclave */
	sgx_destroy_enclave( global_eid );

    return ecall_return;
}
int is_prime( int n ) {

	int p = 1;

	if ( n <= 1 ) {
		p = 0;
	} else if ( n != 2 && (n % 2) == 0) {
		p = 0;
	} else {
		for ( int i = 2; i <= sqrt(n); ++i ) {
	 		// If n is divisible by any number between 2 and n/2, it is not prime
			if ( n % i == 0 ) {
				p = 0;
				break;
			}
		}
	}

    return p;
}