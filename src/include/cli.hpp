#pragma once

#include <cassert> //assert()
#include <chrono> //std::timer
#include <cstdint> //uintxx_t
#include <iostream> //std::cout, std::cerr, std::endl
#include <memory> //std::shared_ptr, make_shared
#include <string> //std::string
#include <thread> //sleep_for()
#include <unistd.h> //STDIN_FILENO
#include <vector> //std::vector
#include "api.hpp" //credCrypt API (all methods and structs)
#include "exceptions.hpp" //all exceptions CredCrypt can throw
#include "secureString.hpp" //secStr class
#include "util.h" //exists
#include "version.h" //VERSION_MAJOR, VERSION_MINOR macros

#ifdef __linux__
#include <termios.h>
#endif

using std::cin;
using std::chrono::milliseconds;
using std::cout;
using std::endl;
using std::this_thread::sleep_for;
using std::vector;

typedef enum
{
    ABRT,
    NO_ACTION,
    CHK_CRED_EXST,
    CHK_KEY_VALID,
    CLR_ALL_CREDS,
    CONFIRM,
    DEL_CRED,
    HELP,
    INS_CRED,
    INPT_PW,
    LIST_ALL_CREDS,
    LOAD_CREDS,
    PRSE_ERR,
    QUIT,
    SAVE_CREDS,
    UPD_CRED,
    VIEW_CRED,
    VIEW_PW
} action;

static const secStr dflt_cred_file("./.cc.crd");

static const secStr enter_pw_msg("Input master password");

static const secStr help_msg("\r\nCommands\r\nClear { N/A }\r\nDelete { account }\r\nExist { account }\r\nInsert { account, username, password } or Insert { account, description, username, password }\r\nHelp: display this menu\r\nList { (optional) include_pw }\r\nLoad { (optional) file_name }\r\nLook { account }\r\nPassword { N/A }\r\nQuit { N/A }\r\nSave { (optional) file_name }\r\nUpdate { account, (optional) username:username, (optional) description:description, (optional) password:password }\r\nValid { N/A }\r\nView { account, (optional) password }\r\n\r\nNote: Once you insert a credential it is tied to the master password entered on the first insertion for the life cycle for it (and any related) credentials. Choose your master password wisely.\r\n");

static const secStr border("#############\r\n");
static const secStr intro_msg("# CredCrypt #\r\n");

struct cred_crypt_state
{
    action action_ = NO_ACTION;
    action prev_action_ = NO_ACTION;
    bool clear_input_ = false;
    bool collect_input_ = true;
    bool confirmed_ = false;
    bool running_ = true;
    credCrypt* instance_ = nullptr;
    int status_ = 0;
    secStr cred_file_ = dflt_cred_file;
    vector<shared_ptr<secStr>> input_;
};
