#ifndef _APP_H_
#define _APP_H_

#include "config.h"
#include "sgx_error.h"	/* sgx_status_t */
#include "sgx_eid.h"	/* sgx_enclave_id_t */

#define RET_SUCCESS 0
#define ERR_PASSWORD_OUT_OF_RANGE 1
#define ERR_WALLET_ALREADY_EXISTS 2
#define ERR_CANNOT_SAVE_WALLET 3
#define ERR_CANNOT_LOAD_WALLET 4
#define ERR_WRONG_MASTER_PASSWORD 5
#define ERR_WALLET_FULL 6
#define ERR_ITEM_DOES_NOT_EXIST 7
#define ERR_ITEM_TOO_LONG 8

#define ENCLAVE_FILENAME "enclave.signed.so"

// item
struct Item {
	char  title[WALLET_MAX_ITEM_SIZE];
	char  username[WALLET_MAX_ITEM_SIZE];
	char  password[WALLET_MAX_ITEM_SIZE];
};
typedef struct Item item_t;

int generate_password(char* p_value, int p_length);
int change_master_password(const char* old_password, const char* new_password);
int add_item(const char* master_password, const item_t* item, const size_t item_size);
int remove_item(const char* master_password, const int index);
int is_wallet(void);
int create_wallet(const char* master_password);
int show_wallet(const char* master_password);
int is_error(int error_code);
void show_help(void);

#endif // !_APP_H_
