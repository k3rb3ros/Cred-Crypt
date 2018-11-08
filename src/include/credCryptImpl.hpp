#pragma once

#include <chrono> //std::chrono::seconds
#include <iostream> //std::iostream std::cout for debugging, std::endl for debugging
#include <memory> // shared_ptr
#include <stdio.h> //rename()
#include <sstream> //std::stringstream
#include <vector> //std::vector container
#include "credential.hpp" //credential class
#include "credentialData.hpp" //credentialData class
#include "headerReader.hpp" //headerReader class
#include "headerWriter.hpp" //headerWriter class
#include "keyChecker.hpp" //keyChecker class
#include "masterKey.hpp"  //masterKey class
#include "parser.hpp" //parser class
#include "registry.hpp" //registry class
#include "secureString.hpp" //secureString class
#include "timer.hpp" //timer class

using std::cerr;
using std::endl;
using std::ifstream;
using std::shared_ptr;
using std::stringstream;
using std::unique_ptr;
using std::vector;

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

    bool credentialExists(secStr& acnt);

    bool credentialIsValid(const credentialData& cred) const;

    bool deleteCredential(secStr& acnt);

    bool inputPassword(secStr& pw);

    bool insertCredential(credentialData& cred);

    bool getCredentials(vector<credentialData>& creds, const bool pw);

    bool getCredential(secStr& acnt, credentialData& cred, const bool pw);

    bool getPassword(secStr& acnt, secStr& pw);

    bool loadCredentialsFromFile(secStr& f_name, secStr& pw);

    bool saveCredentialsToFile(secStr& f_name);

    bool updateCredential(credentialData& cred);
};
