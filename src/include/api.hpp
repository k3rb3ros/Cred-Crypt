#pragma once

/*
 * Written by K3rb3ros
 *
 * This is the top level API that exposes the full functionality of the credential manager */

#include <vector> //std::vector
#include "credCryptImpl.hpp" //credCrypt struct
#include "exceptions.hpp" //NotImplementedException
#include "secureString.hpp" //secStr (secureString) class

struct Credential;

class credCrypt
{
    public:

    //As a user I want to be able to search for credentials by account (name)
    bool credentialExists(secStr& acnt);

    //As a user I want to be able to input my master password and generate my master key
    //As a user I want to be able to know if the password I inputted is correct
    bool inputPassword(secStr& pw);
    
    //As a user I want to know if I need to input my password to use the credential manager
    bool keyIsValid();

    //As a user I want to be able to decrypt and view the password of a given credential
    //or see the entire credential including the password
    Credential viewFullCredential(secStr& acnt, bool pw=false);

    secStr viewPassword(secStr& acnt);

    /* As a user I want to be able to clear all credentials stored in the program
     * (and reset the key) so I can load credentials from a file
     */
    void clearCredentials();

    //As a user I want to be able to delete a credential from the manager
    void deleteCredential(secStr& acnt);

    //As a user I want to be able to insert/update a credential into the manager
    void insertCredential(Credential &cred);

    //As a user I want to be able to see a list of all credentials stored by the manager
    void listAllCredentials(std::vector<Credential>& creds, bool pw=false);

    //As a user I want to be able to to load my stored passwords into the credential manager
    //from the file of my choosing
    void loadCredentialsFromFile(secStr& f_name, secStr& pw);

    void updateCredential(Credential &cred);

    //As a user I want to be able to save a secure representation of my passwords to the file
    // of my choosing
    void saveCredentialsToFile(secStr& f_name);
   
    private:

    credCryptImpl impl_;
};
