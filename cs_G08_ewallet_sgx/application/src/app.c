#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sgx_urts.h>

#include "config.h"
#include "app.h"
#include "sgx_utils.h"
#include "enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/* Application entry */
int SGX_CDECL main(int argc, char** argv) {

    int ret;

    const char* options = ":hnp:c:sax:y:z:r:gl:";
    opterr = 0; // prevent 'getopt' from printing err messages
    char err_message[100];
    int opt, stop = 0;
    int h_flag = 0, g_flag = 0, s_flag = 0, a_flag = 0, n_flag = 0;
    char* p_value = NULL, * l_value = NULL, * c_value = NULL, * x_value = NULL, * y_value = NULL, * z_value = NULL, * r_value = NULL;

    // read user input
    while ((opt = getopt(argc, argv, options)) != -1) {
        switch (opt) {
            // help
        case 'h':
            h_flag = 1;
            break;

            // generate random password
        case 'g':
            g_flag = 1;
            break;
        case 'l': // password's length
            l_value = optarg;
            break;

            // create new wallet
        case 'n':
            n_flag = 1;
            break;

            // master-password
        case 'p':
            p_value = optarg;
            break;

            // change master-password
        case 'c':
            c_value = optarg;
            break;

            // show wallet
        case 's':
            s_flag = 1;
            break;

            // add item
        case 'a': // add item flag
            a_flag = 1;
            break;
        case 'x': // item's title
            x_value = optarg;
            break;
        case 'y': // item's username
            y_value = optarg;
            break;
        case 'z': // item's password
            z_value = optarg;
            break;

            // remove item
        case 'r':
            r_value = optarg;
            break;

            // exceptions
        case '?':
            if (optopt == 'p' || optopt == 'c' || optopt == 'r' ||
                optopt == 'x' || optopt == 'y' || optopt == 'z' ||
                optopt == 'l') {
                sprintf(err_message, "Option -%c requires an argument.", optopt);
            } else if (isprint(optopt)) {
                sprintf(err_message, "Unknown option `-%c'.", optopt);
            } else {
                sprintf(err_message, "Unknown option character `\\x%x'.", optopt);
            }
            stop = 1;
            printf("[ERROR] %s\n", err_message);
            printf("[ERROR] Program exiting\n.");
            break;

        default:
            stop = 1;
            printf("[ERROR] %s\n", err_message);
            printf("[ERROR] Program exiting\n.");
        }
    }

    // perform actions
    if (stop != 1) {
        // show help
        if (h_flag) {
            show_help();
        }

        // generate random password
        else if (g_flag) {
            int pwd_size = WALLET_MAX_ITEM_SIZE - 1;

            if (l_value != NULL) {
                pwd_size = atoi(l_value);
            }

            char* pwd = (char* ) malloc( sizeof(char) * (pwd_size + 1) );
            ret = generate_password(pwd, pwd_size);

            if (is_error(ret)) {
                printf("[ERROR] Failed to generate the password.\n");
            } else {
                printf("[INFO] Password successfully generated.\n");
                printf("The generated password is %s\n", pwd);
            }

            free(pwd);
        }

        // create new wallet
        else if (p_value != NULL && n_flag) {
            ret = create_wallet(p_value);
            if (is_error(ret)) {
                printf("[ERROR] Failed to create new eWallet.\n");
            } else {
                printf("[INFO] eWallet successfully created.\n");
            }
        }

        // change master-password
        else if (p_value != NULL && c_value != NULL) {
            ret = change_master_password(p_value, c_value);
            if (is_error(ret)) {
                printf("[ERROR] Failed to change master-password.\n");
            } else {
                printf("[INFO] Master-password successfully changed.\n");
            }
        }

        // show wallet
        else if (p_value != NULL && s_flag) {
            ret = show_wallet(p_value);
            if (is_error(ret)) {
                printf("[ERROR] Failed to retrieve eWallet.\n");
            } else {
                printf("[INFO] eWallet successfully retrieved.\n");
            }
        }

        // add item
        else if (p_value != NULL && a_flag && x_value != NULL && y_value != NULL && z_value != NULL) {
            item_t* new_item = (item_t* ) malloc(sizeof(item_t));
            strcpy(new_item -> title, x_value);
            strcpy(new_item -> username, y_value);
            strcpy(new_item -> password, z_value);
            ret = add_item(p_value, new_item, sizeof(item_t));
            if (is_error(ret)) {
                printf("[ERROR] Failed to add new item to the eWallet.\n");
            } else {
                printf("[INFO] Item successfully added to the eWallet.\n");
            }
            free(new_item);
        }

        // remove item
        else if (p_value != NULL && r_value != NULL) {
            char* p_end;
            int index = (int) strtol(r_value, & p_end, 10);
            if (r_value == p_end) {
                printf("[ERROR] Option -r requires an integer argument.\n");
            } else {
                ret = remove_item(p_value, index);
                if (is_error(ret)) {
                    printf("[ERROR] Failed to remove item from the eWallet.\n");
                } else {
                    printf("[INFO] Item successfully removed from the eWallet.\n");
                }
            }
        }

        // display help
        else {
            printf("[ERROR] Wrong inputs.\n");
            show_help();
        }
    }

    return 0;
}

void show_help() {
    const char* command = "[-h] [-g [-l password-length]] [-p master-password -n] "\
    "[-p master-password -c new-master-password] [-p master-password -s]"\
    "[-p master-password -a -x item-title -y item-username -z item-password] "\
    "[-p master-password -r item-index]";
    printf("\nUsage: %s %s\n\n", APP_NAME, command);
}

int SGX_CDECL generate_password(char* p_value, int p_length) {

    // Check password policy before calling the enclave 
    if (p_length < 8 || p_length + 1 > WALLET_MAX_ITEM_SIZE) {
        return ERR_PASSWORD_OUT_OF_RANGE;
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, & global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    // generate password
    int generate_password_return;
    ret = ecall_generate_password(global_eid, & generate_password_return, p_value, p_length);
    if (ret != SGX_SUCCESS) {
        return ret;
    }

    /* Call sgx_destroy_enclave to destroy an enclave instance */
    sgx_destroy_enclave(global_eid);

    return generate_password_return;
}

int SGX_CDECL create_wallet(const char* master_password) {

    // check password policy
    if (strlen(master_password) < 8 || strlen(master_password) + 1 > WALLET_MAX_ITEM_SIZE) {
        return ERR_PASSWORD_OUT_OF_RANGE;
    }

    // abort if wallet already exist
    if (is_wallet() == 0) {
        return ERR_WALLET_ALREADY_EXISTS;
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, & global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    // create the wallet
    int create_wallet_return = 0;
    ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_create_wallet(global_eid, & create_wallet_return, master_password);
    if (ret != SGX_SUCCESS)
        print_error_message(ret);

    /* Call sgx_destroy_enclave to destroy an enclave instance */
    sgx_destroy_enclave(global_eid);

    return create_wallet_return;
}

int SGX_CDECL show_wallet(const char* master_password) {

    // check password policy
    if (strlen(master_password) < 8 || strlen(master_password) + 1 > WALLET_MAX_PASSWORD_SIZE) {
        return ERR_PASSWORD_OUT_OF_RANGE;
    }

    if (is_wallet() != 0) {
        return ERR_CANNOT_LOAD_WALLET;
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, & global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    // show the wallet
    int show_wallet_return = 0;
    ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_show_wallet(global_eid, & show_wallet_return, master_password);
    if (ret != SGX_SUCCESS)
        print_error_message(ret);

    /* Call sgx_destroy_enclave to destroy an enclave instance */
    sgx_destroy_enclave(global_eid);
    return show_wallet_return;
}

int SGX_CDECL change_master_password(const char* old_password,
    const char* new_password) {

    // check old password policy
    if (strlen(old_password) < 8 || strlen(old_password) + 1 > WALLET_MAX_PASSWORD_SIZE) {
        return ERR_PASSWORD_OUT_OF_RANGE;
    }

    // check new password policy
    if (strlen(new_password) < 8 || strlen(new_password) + 1 > WALLET_MAX_PASSWORD_SIZE) {
        return ERR_PASSWORD_OUT_OF_RANGE;
    }

    if (is_wallet() != 0) {
        return ERR_CANNOT_LOAD_WALLET;
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, & global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    // change the wallet password
    int change_master_password_return = 0;
    ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_change_master_password(global_eid, & change_master_password_return, old_password, new_password);
    if (ret != SGX_SUCCESS)
        print_error_message(ret);

    /* Call sgx_destroy_enclave to destroy an enclave instance */
    sgx_destroy_enclave(global_eid);

    return change_master_password_return;
}

int SGX_CDECL add_item(const char* master_password,
    const item_t* item, size_t item_size) {

    // check password policy
    if (strlen(master_password) < 8 || strlen(master_password) + 1 > WALLET_MAX_PASSWORD_SIZE) {
        return ERR_PASSWORD_OUT_OF_RANGE;
    }

    // check input length
    if (item_size > sizeof(item_t)) {
        return ERR_ITEM_TOO_LONG;
    }

    if (strlen(item -> title) + 1 > WALLET_MAX_ITEM_SIZE ||
        strlen(item -> username) + 1 > WALLET_MAX_ITEM_SIZE ||
        strlen(item -> password) + 1 > WALLET_MAX_ITEM_SIZE) {
        return ERR_ITEM_TOO_LONG;
    }

    if (is_wallet() != 0) {
        return ERR_CANNOT_LOAD_WALLET;
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, & global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    // add an item to the wallet
    int add_item_return = 0;
    ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_add_item(global_eid, & add_item_return, master_password, (const uint8_t* ) item, item_size);
    if (ret != SGX_SUCCESS)
        print_error_message(ret);

    /* Call sgx_destroy_enclave to destroy an enclave instance */
    sgx_destroy_enclave(global_eid);

    return add_item_return;
}

int SGX_CDECL remove_item(const char* master_password, int index) {

    // check password policy
    if (strlen(master_password) < 8 || strlen(master_password) + 1 > WALLET_MAX_PASSWORD_SIZE) {
        return ERR_PASSWORD_OUT_OF_RANGE;
    }

    // check index bounds
    if (index < 0 || index >= WALLET_MAX_ITEMS) {
        return ERR_ITEM_DOES_NOT_EXIST;
    }

    if (is_wallet() != 0) {
        return ERR_CANNOT_LOAD_WALLET;
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, & global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    // remove an item from the wallet
    int remove_item_return = 0;
    ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_remove_item(global_eid, & remove_item_return, master_password, index);
    if (ret != SGX_SUCCESS)
        print_error_message(ret);

    /* Call sgx_destroy_enclave to destroy an enclave instance */
    sgx_destroy_enclave(global_eid);

    return remove_item_return;
}

int ocall_save_wallet(uint8_t* wallet, size_t wallet_size) {
    FILE* fp = fopen(WALLET_FILE, "w");
    if (fp == NULL) {
        return 1;
    }
    fwrite(wallet, wallet_size, 1, fp);
    fclose(fp);
    return 0;
}

int ocall_load_wallet(uint8_t* wallet, size_t wallet_size) {
    FILE* fp = fopen(WALLET_FILE, "r");
    if (fp == NULL) {
        return 1;
    }
    fread(wallet, wallet_size, 1, fp);
    fclose(fp);
    return 0;
}

void ocall_print_string(const char* str) {
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

int is_wallet(void) {
    FILE* fp = fopen(WALLET_FILE, "r");
    if (fp == NULL) {
        return 1;
    }
    fclose(fp);
    return 0;
}

int is_error(int error_code) {
    char err_message[100];

    // check error case
    switch (error_code) {
    case RET_SUCCESS:
        return 0;

    case ERR_PASSWORD_OUT_OF_RANGE:
        sprintf(err_message, "Password should be at least 8 characters long and at most %d characters long.", WALLET_MAX_ITEM_SIZE);
        break;

    case ERR_WALLET_ALREADY_EXISTS:
        sprintf(err_message, "The eWallet already exists: delete file '%s' first.", WALLET_FILE);
        break;

    case ERR_CANNOT_SAVE_WALLET:
        strcpy(err_message, "Could not save eWallet.");
        break;

    case ERR_CANNOT_LOAD_WALLET:
        strcpy(err_message, "Could not load eWallet.");
        break;

    case ERR_WRONG_MASTER_PASSWORD:
        strcpy(err_message, "Wrong master password.");
        break;

    case ERR_WALLET_FULL:
        sprintf(err_message, "eWallet full (maximum number of items is %d).", WALLET_MAX_ITEMS);
        break;

    case ERR_ITEM_DOES_NOT_EXIST:
        strcpy(err_message, "Item does not exist.");
        break;

    case ERR_ITEM_TOO_LONG:
        sprintf(err_message, "Item too long (maximum size: %d).", WALLET_MAX_ITEM_SIZE);
        break;

    default:
        sprintf(err_message, "Unknown error.");
    }

    // print error message
    printf("[ERROR] %s\n", err_message);
    return 1;
}