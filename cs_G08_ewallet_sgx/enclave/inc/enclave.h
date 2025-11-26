#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#define RET_SUCCESS 0
#define ERR_PASSWORD_OUT_OF_RANGE 1
#define ERR_WALLET_ALREADY_EXISTS 2
#define ERR_CANNOT_SAVE_WALLET 3
#define ERR_CANNOT_LOAD_WALLET 4
#define ERR_WRONG_MASTER_PASSWORD 5
#define ERR_WALLET_FULL 6
#define ERR_ITEM_DOES_NOT_EXIST 7
#define ERR_ITEM_TOO_LONG 8

#define ALPHA_SIZE 26
#define NUM_SIZE 10
#define SYM_SIZE 21

static char numbers[] = "1234567890";
static char letter[]  = "abcdefghijklmnoqprstuvwyzx";
static char letterr[] = "ABCDEFGHIJKLMNOQPRSTUYWVZX";
static char symbols[] = "!@#$%^&*(){}[]:<>?,./";

#define WALLET_MAX_ITEMS 100
#define WALLET_MAX_ITEM_SIZE 100
#define WALLET_MAX_PASSWORD_SIZE 100

// item
struct Item {
	char  title[WALLET_MAX_ITEM_SIZE];
	char  username[WALLET_MAX_ITEM_SIZE];
	char  password[WALLET_MAX_ITEM_SIZE];
};
typedef struct Item item_t;

// wallet
struct Wallet {
	item_t items[WALLET_MAX_ITEMS];
	size_t size;
	char master_password[WALLET_MAX_ITEM_SIZE];
};
typedef struct Wallet wallet_t;

char get_pwd_char(char* charlist, int len);
int seal_wallet(wallet_t* wallet);
int unseal_wallet(wallet_t* wallet);
int printf(const char *fmt, ...);
void print_wallet(const wallet_t* wallet);
void debug_print(int line, int ret_code);

#endif /* !_ENCLAVE_H_ */
