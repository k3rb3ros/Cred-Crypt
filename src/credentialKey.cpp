#include "include/credentialKey.hpp"

using std::array;
using std::copy;

credentialKey::credentialKey(const masterKey& mk): mk_{mk}
{
    if (Random().getBytes((uint8_t*)salt_.data(), SALT_BYTE_SIZE)) { salted_ = true; }
    else { throw RandomDataNotAvailableException{}; }

    #ifdef KEY_DEBUG
    debugKey();
    #endif
}

credentialKey::credentialKey(const masterKey& mk, secStr& salt_hex): mk_{mk}
{
    if (hexDecode(salt_hex.byteStr(), (uint8_t*)salt_.data(), (2*salt_.size())) != nullptr)
    { salted_ = true; }

    #ifdef KEY_DEBUG
    debugKey();
    #endif
}

//if we have the (correct) salt and a valid ref to the master key then we can generate the derrived credential key
bool credentialKey::genKey()
{
    bool success{false};

    // the derrived key is the skein hash of the XOR of the salt and master key
    if (salted_ && mk_.isValid())
    {
        //get a pointer to the master key
        auto mk_data = mk_.keyData();

        //XOR the master key with the derrived salt
        for (uint_fast8_t i{0}; i<keyBase::dataSize(); ++i)
        {
            key_[i] = salt_[i] ^ mk_data[i];
        }

        // in place Skein512 hash that to get the derrived key
        if (skeinHash((uint8_t*)key_.data(),
                      keyBase::byteSize(),
                      (uint8_t*)key_.data(),
                      keyBase::byteSize()))
        {
            success = isValid();
        }
    }

    return success;
}

bool credentialKey::isValid() const
{
    return (salted_ && keyBase::isKeyed());
}

const uint8_t* credentialKey::saltBytes() const
{
    return (salted_ == true) ? (uint8_t*)salt_.data() : nullptr;
}

constexpr size_t credentialKey::byteSize() const
{
    return keyBase::byteSize();
}

constexpr size_t credentialKey::dataSize() const
{
    return keyBase::dataSize();
}

secStr credentialKey::saltHex() const
{
    array<uint8_t, (2*SALT_BYTE_SIZE)+1>hex_buffer{};
    hexEncode((uint8_t*)salt_.data(), hex_buffer.data(), SALT_BYTE_SIZE); //write the salt hex to its temp buffer

    return secStr{hex_buffer.data(), hex_buffer.size()};
}

const uint8_t* credentialKey::keyBytes() const
{
    return (isValid()) ? (uint8_t*)key_.data() : nullptr;
}

void credentialKey::clearKey()
{
    keyBase::clearKey();
}

#ifdef KEY_DEBUG
void credentialKey::debugKey() const
{
    secStr salted_str = salted_ ? secStr("true") : secStr("false");
    secStr valid_str = valid_ ? secStr("true") : secStr("false");
    unique_ptr<uint8_t[]> key_hex(new uint8_t[((2*KEY_BYTE_SIZE)+1)]());
    unique_ptr<uint8_t[]> salt_hex(new uint8_t[((2*SALT_BYTE_SIZE)+1)]());

    hexEncode(key_, key_hex, KEY_BYTE_SIZE);
    hexEncode(salt_, salt_hex, KEY_BYTE_SIZE);

    cout << "credentialKey DEBUG" << endl
    << "{" << endl
    << "\tsalted: " << salted_str << endl
    << "\tvalid: " << valid_str << endl
    << "\tkey: [" << key_hex << endl
    << "\tsalt: [" << salt_hex << endl
    << "\tmaster_key_ptr: " << mk_ << endl
    << "}" << endl;
}
#endif
