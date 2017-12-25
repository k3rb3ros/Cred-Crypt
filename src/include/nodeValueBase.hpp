#pragma once

#include <stdint.h>
#include "secureString.hpp"

/* abstract base class for node values
 * This class only exists to guarantee that getKey()
 * and the ==, < and > operators are defined 
 */
class nodeValueBase
{
    public:

    virtual bool operator ==(nodeValueBase &other) const = 0;
    virtual bool operator <(nodeValueBase &other) = 0;
    virtual bool operator >(nodeValueBase &other) = 0;

    virtual ~nodeValueBase() { /*nop*/ }

    virtual uint64_t* getID() = 0;
};
