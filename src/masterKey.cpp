#include "include/masterKey.hpp"

//TODO enforce more stringent password requirements in the future
static inline bool passwordMeetsRequirements(secStr& pw)
{
    return (pw.size() > 6 && pw.compare("") != 0);
}

//CTOR generates a blank salt (base class inits blank key)
masterKey::masterKey(): keyBase(), salted_(false), keyed_(false)
{
    clearBuff((uint8_t*)salt_, SALT_BYTE_SIZE);
}

//TODO throw an exception if password does not meet requirements
bool masterKey::genKey(secStr& pw)
{
    if (!salted_ && !keyed_)
    {
        if (passwordMeetsRequirements(pw) &&
            Random().getBytes((uint8_t*)salt_, SALT_BYTE_SIZE) &&
            kdf_scrypt(pw.byteStr(), pw.size(),
                       (uint8_t*)salt_, SALT_BYTE_SIZE,
                       SCRYPT_N, SCRYPT_R, SCRYPT_P,
                       (uint8_t*)key_, KEY_BYTE_SIZE) == 0)
        {
            salted_ = true;
            keyed_ = true;
        }
    }

    return keyed_;
}

bool masterKey::inputPassword(secStr& pw)
{
    if (salted_ && !keyed_)
    {
        if (passwordMeetsRequirements(pw) &&
            kdf_scrypt(pw.byteStr(), pw.size(),
                       (uint8_t*)salt_, SALT_BYTE_SIZE,
                       SCRYPT_N, SCRYPT_R, SCRYPT_P,
                       (uint8_t*)key_, KEY_BYTE_SIZE) == 0)
        {
            keyed_ = true;
        } 
    }

    return keyed_;
}

bool masterKey::isSalted() const
{
    return salted_;
}

bool masterKey::setSalt(const uint64_t* salt_words)
{
    salted_ = (memcpy(salt_, salt_words, SALT_BYTE_SIZE) != nullptr);

    return salted_;
}

bool masterKey::isValid() const
{
    return (salted_ && keyed_);
}

const uint8_t* masterKey::keyBytes() const
{ return (salted_ && keyed_) ? (uint8_t*)key_: nullptr; }

//headerReader needs access to the salt bytes even if the key is unsalted
const uint8_t* masterKey::saltBytes() const { return (uint8_t*)salt_; }

void masterKey::clearKey()
{
    ::keyBase::clearKey();
    keyed_ = false;
}

void masterKey::clearSalt()
{
    clearBuff((uint8_t*)salt_, SALT_BYTE_SIZE);
    salted_ = false;
}

masterKey::~masterKey()
{   //Clear the salt from memory
    if (salted_) { clearBuff((uint8_t*)salt_, SALT_BYTE_SIZE); }
}
