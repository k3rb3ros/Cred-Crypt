#pragma once

/*
 * The headerWriter class is used to write the header that is prepended to the CredCrypt
 * serialized credential file
 */

#include "headerBase.hpp"
#include "masterKey.hpp"
#include "ocbMode.h"

class headerWriter : public headerBase
{
    public:

    /**************
    * Constructor *
    **************/
    headerWriter(masterKey& master_key) : headerBase(master_key) {};

    //Destructor
    ~headerWriter() noexcept = default;

    /*****************
    * Public methods *
    *****************/
    //write the header to the output stream
    bool write(ostream& os);

    void setCredSize(const uint64_t size);

    private:
    /***************
    * Private Data *
    ***************/
    bool encrypted_{false};

    bool encryptHeader();
};
