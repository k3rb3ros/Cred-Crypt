/* This class exists to inherit from nodeValueBase in order to allow redBlackTree functionality to be tested
 * in isolation from the credentials */

#include "include/mockNodeValue.hpp"

mockNodeValue::mockNodeValue(uint64_t val) : val_(val)
{
   clearBuff((uint8_t*)id_, ID_BYTE_SIZE);
   stringstream ss;
   ss << val;
   string hash_me = ss.str();
   skeinHash((uint8_t*)hash_me.c_str(), hash_me.size(), (uint8_t*)id_, ID_BYTE_SIZE);
}

inline bool mockNodeValue::operator ==(nodeValueBase &rhs) const
{
    return &rhs == this;
}

inline bool mockNodeValue::operator <(nodeValueBase &rhs)
{
    return *(this->getID()) < *(rhs.getID());
}

inline bool mockNodeValue::operator >(nodeValueBase &rhs)
{
    return *(this->getID()) > *(rhs.getID());
}

uint64_t* mockNodeValue::getID()
{
    return id_;
}

uint64_t mockNodeValue::value() const
{
    return val_;
}
