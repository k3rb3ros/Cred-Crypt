/* This abstract base class defines the necessary data structure and methods to support a cryptographic key */

#pragma once

#include <cstddef> // size_t
#include <cstdint> //uintXX_t types

class keyBase
{
    public:
    /***************
    * constructors *
    ***************/
    //blank key
    explicit keyBase() = default;
    virtual ~keyBase() = 0;

    /*****************
    * public members *
    *****************/
    virtual bool isKeyed() const = 0;
    virtual const uint8_t* keyBytes() const = 0;
    virtual const uint64_t* keyData() const = 0;
    virtual size_t size() const = 0;
    virtual void clearKey() = 0;

    /*******************
    * public operators *
    *******************/
    virtual bool operator == (const keyBase& rhs) const = 0;
    virtual bool operator == (const keyBase* rhs) const = 0;
};
