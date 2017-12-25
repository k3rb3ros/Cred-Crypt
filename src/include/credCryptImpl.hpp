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
#include "redBlackTree.hpp" //redBlackTree class
#include "redBlackTreeNode.hpp" //redBlackTreeNode
#include "secureString.hpp" //secureString class
#include "timer.hpp" //timer class
#include "util.h" //hexEncode()

using std::cerr;
using std::endl;
using std::ifstream;
using std::stringstream;
using std::vector;

struct Credential
{
    secStr account;
    secStr description;
    secStr user_name;
    secStr password;
};

struct credCryptImpl
{
    public:

    bool clean_;
    std::chrono::duration<unsigned int> timeout_;
    keyChecker checker_;
    masterKey master_key_;
    redBlackTree tree_;
    secStr cred_file_;
    timer timer_;

    credCryptImpl();
    ~credCryptImpl();

    bool clearCredentials();

    bool credentialIsValid(const Credential& cred) const;

    bool deleteCredential(secStr& acnt);

    bool insertCredential(Credential& cred);

    //TODO add error string vector
    bool getCredentials(vector<Credential>& creds, const bool pw);

    bool getCredential(secStr& acnt, Credential& cred, const bool pw);

    bool getPassword(secStr& acnt, secStr& pw);

    //TODO add error string vector
    bool loadCredentialsFromFile(secStr& f_name, secStr& pw);

    //TODO add error string vector
    bool saveCredentialsToFile(secStr& f_name);

    bool updateCredential(Credential& cred);
};
