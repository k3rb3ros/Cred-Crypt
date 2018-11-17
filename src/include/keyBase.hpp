/* This abstract base class defines the necessary data structure and methods to support a cryptographic key */

#pragma once

#include <stdint.h> //uintXX_t types
#include <stdlib.h> //size_t
#include "constants.h" //KEY_BYTE_SIZE, SALT_BYTE_SIZE
#include "util.h" //clearBuff()

class keyBase
{
    protected:
    /********************
    * protected members *
    ********************/

    //the key itself
    uint64_t key_[KEY_WORD_SIZE] = { 0 };

    public:
    /***************
    * constructors *
    ***************/
    //blank key
    explicit keyBase() { /*nop*/ }

    /*****************
    * public members *
    *****************/
    size_t size() const { return KEY_BYTE_SIZE; }

    //TODO evaluate if its worth keeping these
    /*******************
    * public operators *
    *******************/
    bool operator == (const keyBase& rhs) const { return this == &rhs; }
    bool operator == (const keyBase* rhs) const { return this == rhs; }

    /*************************
    * public virtual members *
    *************************/
    //derrived class are allowed to override these but they shouldn't need to
    virtual const uint8_t* keyBytes() const { return (uint8_t*)key_; }
    virtual void clearKey() { clearBuff((uint8_t*)key_, KEY_BYTE_SIZE); }

    /*************
    * destructor *
    *************/
    virtual ~keyBase()
    {
        clearBuff((uint8_t*)key_, KEY_BYTE_SIZE);
    }
};
