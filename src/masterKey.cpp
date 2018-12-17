#include "include/masterKey.hpp"
#include "exceptions.hpp"
#include "random.hpp"
#include <algorithm>

using std::any_of;
using std::copy;
using std::fill;

masterKey::masterKey(): keyBase<CIPHER_WORD_SIZE>()
{
    Random random{};
    if (random.getBytes((uint8_t*)salt_.data(), (keyBase::byteSize())))
    {
        salted_ = true;
    }
    else
    {
        throw InvalidSaltHexException{};
    }
}

masterKey::masterKey(secStr& salt_hex): keyBase<CIPHER_WORD_SIZE>()
{
    if (hexDecode(salt_hex.byteStr(), (uint8_t*)salt_.data(), salt_hex.size()) != nullptr)
    {
        salted_ = true;
    }
    else
    {
        throw InvalidSaltHexException{};
    }
}

bool masterKey::passwordMeetsRequirements(const secStr& pw)
{
    return (pw.size() > 6 && pw.compare("") != 0);
}

bool masterKey::isKeyed() const
{
    return keyBase::isKeyed();
}

bool masterKey::isSalted() const
{
    return salted_;
}

bool masterKey::isValid() const
{
    return (salted_ && keyBase::isKeyed());
}

bool masterKey::genKey(secStr& pw)
{
    if (passwordMeetsRequirements(pw))
    {
        // generate a random salt if this is a new key
        if (!salted_)
        {
            salted_ = Random().getBytes((uint8_t*)salt_.data(), SALT_BYTE_SIZE);
        }

        if (salted_)
        {
            kdf_scrypt(pw.byteStr(), pw.size(),
                       (uint8_t*)salt_.data(), keyBase::byteSize(),
                       SCRYPT_N, SCRYPT_R, SCRYPT_P,
                       (uint8_t*)key_.data(), keyBase::byteSize());
        }
    }

    return isKeyed();
}

bool masterKey::inputPassword(secStr& pw)
{
    bool success{false};

    if (salted_)
    {
        if (passwordMeetsRequirements(pw) &&
            kdf_scrypt(pw.byteStr(), pw.size(),
                       (uint8_t*)salt_.data(), keyBase::byteSize(),
                       SCRYPT_N, SCRYPT_R, SCRYPT_P,
                       (uint8_t*)key_.data(), keyBase::byteSize()) == 0)
        {
            success = true;
        }
    }

    return success;
}

bool masterKey::setKey(const key_data_t* key_words)
{
    bool success{false};

    if (!isKeyed())
    {
        copy(key_words, key_words+keyBase::dataSize(), key_.data());

        success = true;
    }

    return success;
}

bool masterKey::setSalt(const key_data_t* salt_words)
{
    if (!salted_ && salt_words != nullptr)
    {
        copy(salt_words, salt_words+keyBase::dataSize(), salt_.data());
        salted_ = true;
    }

    return salted_;
}

const uint8_t* masterKey::keyBytes() const { return (uint8_t*)key_.data(); }

const key_data_t* masterKey::keyData() const { return key_.data(); }

const uint8_t* masterKey::saltBytes() const { return (uint8_t*)salt_.data(); }

void masterKey::clearKey()
{
    keyBase::clearKey();
}

void masterKey::clearSalt()
{
    keyBase::clearSalt();
    salted_ = false;
}
