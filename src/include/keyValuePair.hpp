/*
 * This class encapsulates Key Value pairs that are used in parsing serialized credentials
 */

#pragma once

#include "secureString.hpp"

class keyValuePair
{
    public:

    /***************
    * constructors *
    ***************/
    keyValuePair(char* key, char* value): key_(key), value_(value) { /*nop*/ }

    keyValuePair(std::string key, std::string value): key_(key), value_(value) { /*nop*/ }

    keyValuePair(secStr key, secStr value): key_(key), value_(value) { /*nop*/ }

    secStr key_;
    secStr value_;
};
