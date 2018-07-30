#pragma once

#include <memory> //std::unique_ptr
#include <stdint.h> //uint64_t, int_fast8_t
#include "nodeValueBase.hpp" //nodeValueBase

//abstract base class for node
class nodeBase
{
    public:
    /*************************
    * public virtual members *
    *************************/
    //Ctor
    explicit nodeBase() = default;
    explicit nodeBase(nodeValueBase* value) : value_(value)
    { /*nop*/ }

    virtual uint64_t* getID() = 0;

    //Dtor
    virtual ~nodeBase() { /*nop*/ };

    protected:
    /*****************
    * protected data *
    *****************/
    std::unique_ptr<nodeValueBase> value_{nullptr};
};
