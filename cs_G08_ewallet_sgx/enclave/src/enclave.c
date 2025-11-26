#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sgx_trts.h>

#include "sgx_tseal.h"
#include "enclave.h"
#include "enclave_t.h"

/* Intel SGX Linux documentation: https://download.01.org/intel-sgx/sgx-linux/2.15.1/docs/Intel_SGX_Developer_Reference_Linux_2.15.1_Open_Source.pdf*/

char get_pwd_char(char* charlist, int len) {
    int rand;
    sgx_status_t sgx_return = SGX_ERROR_UNEXPECTED;

    sgx_return = sgx_read_rand((unsigned char* ) & rand, sizeof(int));

    if (sgx_return != SGX_SUCCESS) {
        return -1;
    }

    if (rand < 0) {
        rand *= -1;
    }

    return (charlist[(rand / (RAND_MAX / len))]);
}

int ecall_generate_password(char* p_value, int p_length) {
    int randomizer;

    for (int i = 0; i < p_length; i++) {

        sgx_status_t sgx_return = SGX_ERROR_UNEXPECTED;
        sgx_return = sgx_read_rand((unsigned char* ) & randomizer, sizeof(int));

        if (sgx_return != SGX_SUCCESS) {
            return sgx_return;
        }

        randomizer = randomizer % 4;

        if (randomizer < 0) {
            randomizer *= -1;
        }

        switch (randomizer) {
        case 0:
            p_value[i] = get_pwd_char(numbers, NUM_SIZE);
            break;
        case 1:
            p_value[i] = get_pwd_char(letter, ALPHA_SIZE);
            break;
        case 2:
            p_value[i] = get_pwd_char(letterr, ALPHA_SIZE);
            break;
        case 3:
            p_value[i] = get_pwd_char(symbols, SYM_SIZE);
            break;
        default:
            break;
        }
    }

    p_value[p_length] = '\0';

    return SGX_SUCCESS;
}

int ecall_create_wallet(const char* master_password) {
    wallet_t wallet;

    // create wallet
    strncpy(wallet.master_password, master_password, strlen(master_password) + 1);
    wallet.size = 0;
    return seal_wallet( & wallet);
}

int ecall_show_wallet(const char* master_password) {
    wallet_t wallet;
    int unseal_return = SGX_ERROR_UNEXPECTED;

    // unseal the wallet
    unseal_return = unseal_wallet( & wallet);
    if (unseal_return != SGX_SUCCESS) {
        return unseal_return;
    }

    // verify master-password
    if (strcmp(master_password, wallet.master_password) == 0) {
        print_wallet( & wallet);
        return RET_SUCCESS;
    }

    return ERR_WRONG_MASTER_PASSWORD;
}

int ecall_change_master_password(const char* old_password,
    const char* new_password) {
    wallet_t wallet;
    int unseal_return = SGX_ERROR_UNEXPECTED;

    // unseal the wallet
    unseal_return = unseal_wallet( & wallet);
    if (unseal_return != SGX_SUCCESS)
        return unseal_return;

    // verify master-password
    if (strcmp(old_password, wallet.master_password) == 0) {
        strncpy(wallet.master_password, new_password, strlen(new_password) + 1);
        return seal_wallet( & wallet);
    }

    return ERR_WRONG_MASTER_PASSWORD;
}

int ecall_add_item(const char* master_password,
    const uint8_t* item, size_t item_size) {

    // check the size of the item to be added
    if (item_size > sizeof(item_t)) {
        return ERR_ITEM_TOO_LONG;
    }

    wallet_t wallet;
    int unseal_return = SGX_ERROR_UNEXPECTED;

    // unseal the wallet
    unseal_return = unseal_wallet( & wallet);
    if (unseal_return != SGX_SUCCESS)
        return unseal_return;

    // verify master-password
    if (strcmp(master_password, wallet.master_password) == 0) {
        size_t wallet_size = wallet.size;

        // verify the wallet size
        if (wallet_size >= WALLET_MAX_ITEMS)
            return ERR_WALLET_FULL;

        // add item to wallet
        wallet.items[wallet_size] = * ((const item_t* ) item);
        ++wallet.size;

        return seal_wallet( & wallet);
    }
    return ERR_WRONG_MASTER_PASSWORD;
}

int ecall_remove_item(const char* master_password, int index) {
    wallet_t wallet;
    int unseal_return = SGX_ERROR_UNEXPECTED;

    // unseal the wallet
    unseal_return = unseal_wallet( & wallet);
    if (unseal_return != SGX_SUCCESS)
        return unseal_return;

    // verify master-password
    if (strcmp(master_password, wallet.master_password) == 0) {
        size_t wallet_size = wallet.size;

        // check if item exists
        if ((size_t) index >= wallet_size)
            return ERR_ITEM_DOES_NOT_EXIST;

        // remove item from wallet
        for (size_t i = (size_t) index; i < wallet_size - 1; ++i)
            wallet.items[i] = wallet.items[i + 1];

        // decresase size of the wallet
        --wallet.size;

        return seal_wallet( & wallet);
    }

    return ERR_WRONG_MASTER_PASSWORD;
}

int seal_wallet(wallet_t* wallet) {

    /*
    sgx_status_t SGXAPI sgx_seal_data(
    const uint32_t additional_MACtext_length,
    const uint8_t *p_additional_MACtext,
    const uint32_t text2encrypt_length,
    const uint8_t *p_text2encrypt,
    const uint32_t sealed_data_size,
    sgx_sealed_data_t *p_sealed_data);
    */

    const uint32_t wallet_sealed_size = sizeof(wallet_t) + sizeof(sgx_sealed_data_t);
    sgx_sealed_data_t* wallet_sealed = (sgx_sealed_data_t* ) malloc(wallet_sealed_size);

    // seal the wallet
    sgx_status_t sgx_return = SGX_ERROR_UNEXPECTED;
    sgx_return = sgx_seal_data(0, NULL, sizeof(wallet_t), (const uint8_t* ) wallet, wallet_sealed_size, wallet_sealed);
    if (sgx_return != SGX_SUCCESS) {
        free(wallet_sealed);
        return sgx_return;
    }

    // save the sealed wallet with an ocall
    int save_wallet_return = 0;
    sgx_return = SGX_ERROR_UNEXPECTED;
    sgx_return = ocall_save_wallet( & save_wallet_return, (uint8_t* ) wallet_sealed, wallet_sealed_size);

    free(wallet_sealed);
    if (sgx_return != SGX_SUCCESS || save_wallet_return != 0)
        return ERR_CANNOT_SAVE_WALLET;

    return RET_SUCCESS;
}

int unseal_wallet(wallet_t* wallet) {

    /*
    sgx_status_t sgx_unseal_data(
    const sgx_sealed_data_t * p_sealed_data,
    uint8_t * p_additional_MACtext,
    uint32_t * p_additional_MACtext_length,
    uint8_t * p_decrypted_text,
    uint32_t * p_decrypted_text_length);
    */

    uint32_t wallet_sealed_size = sizeof(wallet_t) + sizeof(sgx_sealed_data_t);
    uint8_t* wallet_sealed = (uint8_t* ) malloc(wallet_sealed_size);
    sgx_status_t sgx_return = SGX_ERROR_UNEXPECTED;
    int load_wallet_return;

    // load the sealed wallet with an ocall
    sgx_return = ocall_load_wallet( & load_wallet_return, (uint8_t* ) wallet_sealed, wallet_sealed_size);
    if (sgx_return != SGX_SUCCESS || load_wallet_return != 0) {
        free(wallet_sealed);
        return ERR_CANNOT_LOAD_WALLET;
    }

    // unseal the wallet
    uint32_t wallet_size = sizeof(wallet_t);
    sgx_return = SGX_ERROR_UNEXPECTED;
    sgx_return = sgx_unseal_data((const sgx_sealed_data_t* ) wallet_sealed, NULL, NULL, (uint8_t* ) wallet, & wallet_size);
    free(wallet_sealed);

    return sgx_return;
}

/* printf: Invokes OCALL to display the enclave buffer to the terminal. */
int printf(const char* fmt, ...) {
    char buf[BUFSIZ] = {
        '\0'
    };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int) strnlen(buf, BUFSIZ - 1) + 1;
}

void print_wallet(const wallet_t* wallet) {
    printf("\n-----------------------------------------\n"
        "Simple password eWallet."
        "\n-----------------------------------------\n"
        "Number of items: %lu\n",
        wallet -> size
    );

    for (size_t i = 0; i < wallet -> size; i++) {
        printf("\n#%d -- %s"
            "\nUsername: %s"
            "\nPassword: %s\n",
            i,
            wallet -> items[i].title,
            wallet -> items[i].username,
            wallet -> items[i].password
        );
    }
    printf("\n------------------------------------------\n\n");
}

void debug_print(int line, int ret_code) {
    // prints the return code of a given operation while specifying the line of the print
    printf("\nline: %d ret_code:%d\n", line, ret_code);
}