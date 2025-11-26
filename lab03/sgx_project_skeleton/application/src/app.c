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
    uint32_t nbytes;

    //Chamada ecall para o mundo seguro para buscar número de bytes a ser lido do disco
    ret = ecall_get_size(global_eid, &ecall_return);
    if ( ret != SGX_SUCCESS){
        print_error_message(ret);

        return -1;
    }
    else if (ecall_return == (int)0xFFFFFFFF){
        printf("Erro ao calcular o número de bytes\n");
        return -1;
    }
    nbytes = (uint32_t)ecall_return;    // O valor retornado é o tamanho do sealed_data
    unsigned char * sealed_data = (unsigned char*)malloc(nbytes);
    unsigned char * new_prime_sealed = (unsigned char*)malloc(nbytes);
    
    // nbytes é o tamanho do buffer (sealed_data_t)
    int control = load_prime((int *)sealed_data, nbytes);

    //printf("Primeiro Control: %d\n", control);
    if (control == 1){
        // Ficheiro não existe. Será gerado um novo primo sem comparação.
        printf("Ficheiro %s de chave não encontrado. Gerando novo primo selado...\n", PRIME_FILENAME);
        ret = ecall_get_rand_prime_sealed(global_eid, &ecall_return, (int)nbytes,new_prime_sealed);
        if ( ret != SGX_SUCCESS){
            print_error_message(ret);
            return -1;
        }
    }
    else{
        // Ficheiro existe. Descelar, gerar e selar.
        printf("Ficheiro %s encontrado Descelando...\n", PRIME_FILENAME);
        ret = ecall_get_sealed_data(global_eid,&ecall_return,(int)nbytes,sealed_data,new_prime_sealed);
        if ( ret != SGX_SUCCESS){
            print_error_message(ret);
            return -1;
        }
        if(ecall_return == -1){
            printf("Erro SGX na descelagem de dados dentro da enclave\n");
            return -1;
        }
        else if(ecall_return == -2){
            printf("Erro SGX na Selagem dos dados dentro da enclave\n");
        }
    }

    control = save_prime((int *) new_prime_sealed, nbytes);

    if (control == 1){
        printf("Erro ao salvar o new Prime\n");

        return -1;
    }

    printf("Ficheiro gravado com Sucesso no Disco!!\n");
    /* Destroy the enclave */
    free(sealed_data);
    free(new_prime_sealed);
	sgx_destroy_enclave( global_eid );

    return ecall_return;
}

int load_prime( int* prime, const size_t prime_size ) {

	FILE *fp = fopen( PRIME_FILENAME, "r" );
	if ( fp == NULL ){
		return 1;
	}
	fread( prime, prime_size, 1, fp );
	fclose( fp );
	return 0;
}

int save_prime( const int* prime, const size_t prime_size ) {

	FILE *fp = fopen( PRIME_FILENAME, "w");
	if ( fp == NULL ){
		return 1;
	}
	fwrite( prime, prime_size, 1, fp);
	fclose( fp );
	return 0;
}
