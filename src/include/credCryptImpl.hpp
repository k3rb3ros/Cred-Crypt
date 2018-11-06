#pragma once

#include <chrono> //std::chrono::seconds
#include <iostream> //std::iostream std::cout for debugging, std::endl for debugging
#include <stdio.h> //rename()
#include <sstream> //std::stringstream
#include <vector> //std::vector container
#include "credential.hpp" //credential class
#include "headerReader.hpp" //headerReader class
#include "headerWriter.hpp" //headerWriter class
#include "keyChecker.hpp" //keyChecker class
#include "masterKey.hpp"  //masterKey class
#include "ocbMode.h" //ocbSetup(), ocbEncrypt()
#include "parser.hpp" //parser class
#include "registry.hpp" //registry class
#include "secureString.hpp" //secureString class
#include "timer.hpp" //timer class
#include "util.h" //hexEncode()

using std::cerr;
using std::endl;
using std::ifstream;
using std::stringstream;
using std::vector;

struct credential_data final
{
    secStr account{};
    secStr description{};
    secStr user_name{};
    secStr password{};
};

class credCryptImpl final
{
    public:

    bool clean_{true};
    std::chrono::duration<unsigned int> timeout_{};
    keyChecker checker_{};
    masterKey master_key_{};
    registry<credential> reg_;
    secStr cred_file_{};
    timer timer_;

    credCryptImpl();
    ~credCryptImpl();

    bool clearCredentials();

    bool credentialIsValid(const credential_data& cred) const;

    bool deleteCredential(secStr& acnt);

    bool insertcredential(credential_data& cred);

    //TODO add error string vector
    bool getCredentials(vector<credential_data>& creds, const bool pw);

    bool getCredential(secStr& acnt, credential_data& cred, const bool pw);

    bool getPassword(secStr& acnt, secStr& pw);

    //TODO add error string vector
    bool loadCredentialsFromFile(secStr& f_name, secStr& pw);

    //TODO add error string vector
    bool saveCredentialsToFile(secStr& f_name);

    bool updateCredential(credential_data& cred);
};
