#include "enclave_t.h"
#include "enclave.h"
#include <sgx_tseal.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

/**
 * @brief calcula um novo número primo diferente do antigo:Descelagem do primo antigo recebido, 
 * gera um novo primo aleatório e faz a selagem do mesmo.
 * 
 * @param size                  Tamanho total do buffer selado (garantido pelo Host/EDL).
 * @param old_prime_sealed      Ponteiro [in] para a chave primária antiga selada.
 * @param new_prime_sealed      Ponteiro [out] para a chave primária nova selada.
 * @return int                  0 em caso de sucesso; -1 em caso de falha na operação SGX.
 */
int ecall_get_sealed_data(int size,unsigned char * old_prime_sealed, unsigned char *new_prime_sealed){

    int buf_size = 4; //tamanho em bytes do valor a ser gerado 
    unsigned char buf[buf_size];    //Buffer temporário para bytes aleatórios

    // ---  DESCELAGEM (UNSEAL) Do PIMO ANTIGO ---
    
	uint32_t old_prime;
    uint32_t data_size = buf_size; //tamanho do buffer de decifragem
    sgx_status_t sgx_status = data_unseal(old_prime_sealed, &old_prime, &data_size);

	if(sgx_status != SGX_SUCCESS){
		return -1; //Erro ao descelar os dados
	}

   // ---  GERAÇÃO DO NOVO PRIMO SEGURO ---
	uint32_t p, new_prime;
	do {
		// Generate a random prime
		p = 0;
		do {
			sgx_read_rand(buf,buf_size); // Lê 4 bytes aleatórios seguros da SGX
			
			// Converte 4 bytes aleatórios para um único uint32_t
            new_prime = (int)buf[0] | (int)buf[1] << 8 | (int)buf[2] << 16 | (int)buf[3] << 24;
			p = is_prime( new_prime );
		} while( p != 1 );	// Repete até gerar um número primo

	} while( new_prime == old_prime ); // Repete até que o novo primo seja diferente do antigo

	// --- SELAGEM (SEAL) Do NOVO PRIMO ---
	
    sgx_sealed_data_t sealed_data;	// Estrutura local para armazenar o resultado da selagem

	// Cifra e autentica o novo primo (4 bytes)
    sgx_status = data_seal(&sealed_data, (uint8_t *)&new_prime,sizeof(uint32_t));

	if(sgx_status != SGX_SUCCESS){
		return -2; //Erro ao Selar os dados
	}
    
    // Copia os dados da variável local para o buffer de saída
	memcpy(new_prime_sealed, &sealed_data, sizeof(sgx_sealed_data_t));

	return 0;
}
/**
 * @brief Calcula e retorna o tamanho necessário (em bytes) para armazenar 
 * os dados selados no disco.
 * * * Esta função é chamada pelo Host para que ele possa alocar o buffer de saída
 * antes de chamar ecall_get_sealed_data.
 * * @return int Retorna o tamanho total (header + MAC + dados cifrados) da estrutura sgx_sealed_data_t.
 */
int ecall_get_size(){

    int status = 0;
	// sgx_calc_sealed_data_size calcula o tamanho total da estrutura selada.
    // O 0 representa o tamanho do texto adicional (AAD), que não estamos a usar.
    // O 4 representa o tamanho do texto em bytes a ser cifrado (sizeof(uint32_t)).

    status = sgx_calc_sealed_data_size(0,4);
	
    return status; // Retorna o tamanho calculado. Este valor será usado pelo Host para alocar memória.
}
/**
 * @brief Gera um novo número primo aleatório seguro, sela-o e copia o 
 * resultado para o buffer de saída do Host.
 * 
 * @param prime_sealed [out] Ponteiro para o buffer de saída do Host para os dados selados.
 * @return int Retorna 0 em caso de sucesso; um código negativo em caso de erro SGX.
 */
int ecall_get_rand_prime_sealed(int size, unsigned char * prime_sealed){
	unsigned char buf[4];
	int p = 0;
	uint32_t new_prime = 0;
	do {
		sgx_read_rand(buf,4);
		
		new_prime = (uint32_t)buf[0] | (uint32_t)buf[1] << 8 | (uint32_t)buf[2] << 16 | (uint32_t)buf[3] << 24;
		p = is_prime(new_prime);
	} while (p != 1); // Repete até ser primo

	// --- SELAGEM (SEAL) Do NOVO PRIMO ---
    sgx_sealed_data_t sealed_data;	// Estrutura local para armazenar o resultado da selagem

	// Cifra e autentica o novo primo (4 bytes)
    sgx_status_t sgx_status = data_seal(&sealed_data, (uint8_t *)&new_prime,sizeof(uint32_t));

	if(sgx_status != SGX_SUCCESS){
		return -2; //Erro ao Selar os dados
	}
	// Copia os dados da variável local para o buffer de saída
	memcpy(prime_sealed, &sealed_data, sizeof(sgx_sealed_data_t));
	return 0;
}
/**
 * @brief Descela (Unseal) os dados recebidos para obter o texto original (uint32_t).
 * @param data_sealed               Buffer que contém os dados selados e autenticados (entrada).
 * @param p_decrypted_text          Ponteiro para onde o número primo original será escrito (saída).
 * @param p_decrypted_text_length   Ponteiro para o tamanho dos dados decifrados (deve ser 4 bytes).
 * @return sgx_status_t             Status da operação (indica se foi bem-sucedida).
 */
sgx_status_t data_unseal(unsigned char *data_sealed,uint32_t *p_decrypted_text, uint32_t *p_decrypted_text_length){

    sgx_status_t sgx_status;
    sgx_status = sgx_unseal_data((sgx_sealed_data_t *) data_sealed,NULL,NULL, (uint8_t *)p_decrypted_text,p_decrypted_text_length);
    
    return sgx_status;
}
/**
 * @brief Sela (Seal) o novo número primo, cifrando-o para armazenamento seguro.
 * @param p_sealed_data             Ponteiro para o buffer onde a estrutura selada será escrita (saída).
 * @param p_text2encrypt            Ponteiro para os dados a serem cifrados (o novo número primo).
 * @param text2encrypt_length       Comprimento (em bytes) dos dados a cifrar (4 bytes).
 * @return sgx_status_t             Status da operação (indica se foi bem-sucedida).
 */
sgx_status_t data_seal(sgx_sealed_data_t * p_sealed_data, uint8_t *p_text2encrypt, uint32_t text2encrypt_length){

    // Calcula o tamanho necessário para o buffer de saída (dados cifrados + cabeçalho).
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0,text2encrypt_length);

    sgx_status_t sgx_status;
    sgx_status = sgx_seal_data(0,NULL,text2encrypt_length, p_text2encrypt, sealed_data_size, p_sealed_data);

    return sgx_status;
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

