#include "include/masterKey.hpp"
#include <algorithm>

using std::any_of;
using std::copy;
using std::fill;

masterKey::masterKey(): keyBase<CIPHER_WORD_SIZE>()
{}

masterKey::masterKey(secStr& salt_hex): keyBase<CIPHER_WORD_SIZE>()
{
    hexDecode(salt_hex.byteStr(), (uint8_t*)salt_.data(), salt_hex.size());
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
    if (!salted_ && !isKeyed())
    {
        if (passwordMeetsRequirements(pw) &&
            Random().getBytes((uint8_t*)salt_.data(), SALT_BYTE_SIZE) &&
            kdf_scrypt(pw.byteStr(), pw.size(),
                       (uint8_t*)salt_.data(), SALT_BYTE_SIZE,
                       SCRYPT_N, SCRYPT_R, SCRYPT_P,
                       (uint8_t*)key_.data(), KEY_BYTE_SIZE) == 0)
        {
            salted_ = true;
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
                       (uint8_t*)salt_.data(), SALT_BYTE_SIZE,
                       SCRYPT_N, SCRYPT_R, SCRYPT_P,
                       (uint8_t*)key_.data(), KEY_BYTE_SIZE) == 0)
        {
            success = true;
        }
    }

    return success;
}

bool masterKey::setKey(const uint64_t* key_words)
{
    bool success{false};

    if (!isKeyed())
    {
        copy(key_words, key_words+KEY_BYTE_SIZE, key_.data());

        success = true;
    }

    return success;
}

bool masterKey::setSalt(const uint64_t* salt_words)
{
    if (!salted_ && salt_words != nullptr)
    {
        copy(salt_words, salt_words+SALT_BYTE_SIZE, salt_.data());
        salted_ = true;
    }

    return salted_;
}

const uint8_t* masterKey::keyBytes() const { return (uint8_t*)key_.data(); }

const uint64_t* masterKey::keyData() const { return key_.data(); }

const uint8_t* masterKey::saltBytes() const { return (uint8_t*)salt_.data(); }

size_t masterKey::size() const { return key_.size(); }

void masterKey::clearKey()
{
    keyBase::clearKey();
}

void masterKey::clearSalt()
{
    keyBase::clearSalt();
    salted_ = false;
}
