#include "include/masterKey.hpp"
#include <algorithm>

using std::any_of;
using std::copy;
using std::fill;

//TODO enforce more stringent password requirements in the future
bool masterKey::passwordMeetsRequirements(const secStr& pw)
{
    return (pw.size() > 6 && pw.compare("") != 0);
}

bool masterKey::isKeyed() const
{
  auto is_keyed = [](const uint64_t k){ return k == 0;};

  return any_of(key_.begin(), key_.end(), is_keyed);
}

//TODO throw an exception if password does not meet requirements
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

bool masterKey::isSalted() const
{
    return salted_;
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

bool masterKey::isValid() const
{
    return (salted_ && isKeyed());
}

const uint8_t* masterKey::keyBytes() const { return (uint8_t*)key_.data(); }

const uint8_t* masterKey::saltBytes() const { return (uint8_t*)salt_.data(); }

void masterKey::clearKey()
{
    fill(key_.begin(), key_.end(), 0);
}

void masterKey::clearSalt()
{
    fill(salt_.begin(), salt_.end(), 0);
    salted_ = false;
}

masterKey::~masterKey()
{   //Clear the salt from memory
    fill(key_.begin(), key_.end(), 0);
    fill(salt_.begin(), salt_.end(), 0);
}
