#pragma once

/*
 * The headeReader is used to read and verify the contents of a CredCrypt header
 * verifying that the file was not modified and that the password + salt used to
 * generate the masterKey are correct.
 */

#include <iostream> //std::istream
#include "headerBase.hpp" //headerBase class
#include "masterKey.hpp" //masterKeyClass
#include "ocbMode.h" //ocbDecrypt()
#include "secureString.hpp" //secStr class

using std::istream;

class headerReader : public headerBase
{
    public:
    /**************
    * Constructor *
    **************/
    explicit headerReader(masterKey& master_key) : headerBase(master_key) {};

    /*************
    * Destructor *
    *************/
    ~headerReader() noexcept = default;

    /*****************
    * Public methods *
    *****************/

    //read the header from the ifs stream
    bool read(istream &is);

    //return true if the header data, salt, and key are correct
    bool headerIsValid(secStr &pw);

    //return the size from the header
    uint64_t getCredsSize();

    private:
    /***************
    * Private Data *
    ***************/
    bool decrypted_{false};
    bool read_{false};

    /******************
    * Private Members *
    ******************/
    bool decryptHeaderData();
};
