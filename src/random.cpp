#include "include/random.hpp"

using std::make_unique;
using std::unique_ptr;

Random::Random()
{
    if (exists(HW_RNG)) //hardware random number device found on some *nix systems
    {
        rand.open(HW_RNG, std::ifstream::binary);
    }
    else if (exists(PRNG)) //*nix psuedo random number device
    {
        rand.open(PRNG, std::ifstream::binary);
    }
    else if (exists(LRNG)) //random is more secure but it often has to little entropy to use
    {
        rand.open(LRNG, std::ifstream::binary);
    }

    rand.good() == true ? is_good = true : is_good = false; //set the is_good flag
}

inline bool Random::isGood()
{
    return is_good;
}

bool Random::getBytes(uint8_t* buffer, const size_t byte_size)
{
    if (rand.good())
    {
        rand.read((char*)buffer, byte_size);
        if (rand.good()) { return true; }
    }
    return false;
}

uint8_t Random::getByte()
{
    if (rand.good())
    {
        uint8_t num;
        rand >> num;

        return num;
    }

    return 0;
}

uint8_t Random::getByte(const uint8_t upper_lim)
{
    if (rand.good())
    {
        uint8_t num;
        rand >> num;

        return num%(upper_lim+1);
    }

    return 0;
}

uint32_t Random::getInt()
{
    if(rand.good())
    {
        uint32_t num;
        uint8_t* fill = (uint8_t*)&num;
        rand >> fill[0] >> fill[1] >> fill[2] >> fill[3];

        return num;
    }

    return 0;
}

uint32_t Random::getInt(const uint32_t upper_lim)
{
    if (rand.good())
    {
        uint32_t num;
        uint8_t* fill = (uint8_t*)&num;
        rand >> fill[0] >> fill[1] >> fill[2] >> fill[3];

        return num%(upper_lim+1);
    }

    return 0;
}

uint64_t Random::getLong()
{
    if (rand.good())
    {
        uint64_t num;
        uint8_t* fill = (uint8_t*)&num;
        rand >> fill[0] >> fill[1] >> fill[2] >> fill[3] 
             >> fill[4] >> fill[5] >> fill[6] >> fill[7];

        return num;
    }

    return 0;
}

uint64_t Random::getLong(const uint64_t upper_lim)
{
    if (rand.good())
    {
        uint64_t num;
        uint8_t* fill = (uint8_t*)&num;
        rand >> fill[0] >> fill[1] >> fill[2] >> fill[3] 
             >> fill[4] >> fill[5] >> fill[6] >> fill[7];

        return num%(upper_lim+1);
    }

    return 0;
}

unique_ptr<uint8_t[]> Random::getBytes(const size_t byte_size)
{
    unique_ptr<uint8_t[]> bytes{};
    if (rand.good())
    {
        bytes = make_unique<uint8_t[]>(byte_size);
        rand.read((char*)bytes.get(), byte_size);
    }

    return bytes;
}

Random::~Random()
{
    if(rand.is_open()) { rand.close(); };
}
