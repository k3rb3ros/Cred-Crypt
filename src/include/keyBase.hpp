#pragma once

#include <algorithm> //std::any_of, std::equal
#include <array> // std::array
#include <cstddef> // size_t
#include <cstdint> // uintXX_t types

using key_data_t = uint64_t;

/* This base class defines the necessary data structures and methods to support a salted cryptographic key */
template <const size_t WORD_SIZE>
class keyBase
{
    public:
    /***************
    * constructors *
    ***************/
    //blank key
    explicit keyBase() = default;
    virtual ~keyBase()
    {
        /* clear all sensative values on destruction */
        std::fill(salt_.begin(), salt_.end(), 0);
        std::fill(key_.begin(), key_.end(), 0);
    }

    /*****************
    * public members *
    *****************/
    // any non zero value for key is considered to be a valid key
    bool isKeyed() const
    {
        auto is_keyed = [](const key_data_t k){ return k != 0;};

        return std::any_of(key_.begin(), key_.end(), is_keyed);
    }
    const uint8_t* keyBytes() const { return static_cast<uint8_t*>(key_.data()); }
    constexpr size_t byteSize() const { return key_.size(); }
    constexpr size_t dataSize() const { return key_.size() / sizeof(key_data_t); }
    void clearKey() { std::fill(key_.begin(), key_.end(), 0); }
    void clearSalt() { std::fill(salt_.begin(), key_.end(), 0); }

    /*******************
    * public operators *
    *******************/
    bool operator == (const keyBase& rhs) const
    { return std::equal(key_.begin(), key_.end(), rhs.key_.begin()); };

    protected:
    bool salted_{false};
    std::array<key_data_t, WORD_SIZE> salt_{};
    std::array<key_data_t, WORD_SIZE> key_{};

};
