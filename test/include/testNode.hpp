#pragma once

#include <cstdint> //uint64_t
#include "constants.h" //ID_WORD_SIZE
#include "hash.h" //skeinHash()
#include "identifier.hpp"

class testNode
{
    private:
    identifier id_{};
    uint64_t val_{0};

    public:
    /**************
    * Constructor *
    **************/
    testNode(uint64_t val): val_{val}
    {
        auto id = id_.data();
        id[0] = val;
    }

    inline bool operator ==(testNode &rhs) const { return id_ == rhs.id_; }
    inline bool operator <(testNode &rhs) const { return id_ < rhs.id_; }
    inline bool operator >(testNode &rhs) const { return id_ > rhs.id_; }

    inline identifier getIdentifier() { return id_; }

    inline uint64_t get_value() const { return val_; }
};
