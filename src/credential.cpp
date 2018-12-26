#include "include/credential.hpp"

#include "cryptoStructs.h" //key_pair type and skein_hash type
#include "ctrMode.h" //ctrEncrypt(), ctrDecypt()
#include "hash.h" //skeinHash()
#include "random.hpp" //Random().getBytes()
#include "skeinApi.h"
#include "util.h" //compareWordBuff(), hexEncode(), hexDecode(), isEmpty()
#include "util.hpp" //clearBuffer()

#ifdef DBG_CRED
using std::cout;
using std::endl;
#endif
using std::array;
using std::copy;
using std::fill;
using std::make_unique;
using std::move;
using std::ofstream;
using std::unique_ptr;

/***************
* constructors *
****************/
credential::credential(secStr& account,
                       secStr& username,
                       secStr& password,
                       const masterKey& master_key
                      ):
    id_{account},
    acnt_len_{account.size()},
    uname_len_{username.size()},
    pw_len_{password.size()},
    account_{ make_unique<uint8_t[]>(acnt_len_) },
    username_{ make_unique<uint8_t[]>(uname_len_) },
    password_{ make_unique<uint8_t[]>(pw_len_) },
    master_key_{master_key},
    derrived_key_(master_key_)
{
    if (acnt_len_ > 0 && uname_len_ > 0 && pw_len_ > 0)
    {
        //generate the salt and in turn the derrived key
        if (master_key_.isValid() && derrived_key_.genKey())
        {
                //copy the data into the credential
                copy(account.byteStr(), (account.byteStr() + acnt_len_), account_.get());
                copy(username.byteStr(), (username.byteStr() + uname_len_), username_.get());
                copy(password.byteStr(), (password.byteStr() + pw_len_), password_.get());

                //encrypt the data
                encryptValue(account_.get(), acnt_len_, &derrived_key_);
                encryptValue(username_.get(), uname_len_, &derrived_key_);
                encryptValue(password_.get(), pw_len_, &derrived_key_);

                derrived_key_.clearKey(); //clear the derrived key
                hashCredential(hash_); //update the credential hash
        }
        else
        {
            throw InvalidKeyException{};
        }
    }
    else
    {
        throw InvalidDataException{};
    }

    #ifdef DBG_CRED
    debugCredential();
    #endif
}

credential::credential(secStr& account,
                       secStr& description,
                       secStr& username,
                       secStr& password,
                       const masterKey& master_key
                      ):
    id_{account},
    acnt_len_{account.size()},
    desc_len_{description.size()},
    uname_len_{username.size()},
    pw_len_{password.size()},
    account_{ make_unique<uint8_t[]>(acnt_len_) },
    description_{make_unique<uint8_t[]>(desc_len_) },
    username_{ make_unique<uint8_t[]>(uname_len_) },
    password_{ make_unique<uint8_t[]>(pw_len_) },
    master_key_(master_key),
    derrived_key_(master_key_)
{
    if (acnt_len_ > 0 && uname_len_ > 0 && pw_len_ > 0)
    {
        if (master_key_.isValid() && derrived_key_.genKey())
        {
            //copy data into the credential
            copy(account.byteStr(), (account.byteStr() + acnt_len_), account_.get());
            copy(username.byteStr(), (username.byteStr() + uname_len_), username_.get());
            copy(password.byteStr(), (password.byteStr() + pw_len_), password_.get());

            //encrypt the data
            encryptValue(account_.get(), acnt_len_, &derrived_key_);
            encryptValue(password_.get(), pw_len_, &derrived_key_);
            encryptValue(username_.get(), uname_len_, &derrived_key_);

            // handle optional description
            if (desc_len_ > 0)
            {
                copy(description.byteStr(), (description.byteStr() + desc_len_), description_.get());
                encryptValue(description_.get(), desc_len_, &derrived_key_);
            }

            derrived_key_.clearKey(); //clear the key
            hashCredential(hash_); //update the credential hash
        }
        else
        {
            throw InvalidKeyException{};
        }
    }
    else
    {
        throw InvalidDataException{};
    }

    #ifdef DBG_CRED
    debugCredential();
    #endif
}

credential::credential(credentialData& raw_cred,
                       const masterKey& master_key)
: credential(raw_cred.account_,
             raw_cred.description_,
             raw_cred.password_,
             raw_cred.username_,
             master_key)
{}

//persistent credential constructor
credential::credential(secStr& account_hex,
                       secStr& desc_hex,
                       secStr& uname_hex,
                       secStr& pw_hex,
                       secStr& id_hex,
                       secStr& hash_hex,
                       secStr& salt_hex,
                       const masterKey& master_key
                      ):
    acnt_len_{account_hex.size()/2},
    desc_len_{desc_hex.size()/2},
    uname_len_{uname_hex.size()/2},
    pw_len_{pw_hex.size()/2},
    account_{ make_unique<uint8_t[]>(acnt_len_) },
    description_{make_unique<uint8_t[]>(desc_len_) },
    username_{ make_unique<uint8_t[]>(uname_len_) },
    password_{ make_unique<uint8_t[]>(pw_len_) },
    master_key_(master_key),
    derrived_key_(master_key_, salt_hex)
{
    if (account_hex.size() > 0 && (account_hex.size() % 2) == 0 &&
        uname_hex.size() > 0 && (uname_hex.size() % 2) == 0 &&
        pw_hex.size() > 0 && (pw_hex.size() % 2) == 0 &&
        id_hex.size() == (2*ID_BYTE_SIZE) &&
        salt_hex.size() > 0 && (2*SALT_BYTE_SIZE) &&
        hash_hex.size() > 0 && (2*HASH_BYTE_SIZE)
       )
    {
        //set the lengths of the stored text fields
        acnt_len_ = (account_hex.size()/2);
        desc_len_ = (desc_hex.size()/2);
        uname_len_ = (uname_hex.size()/2);
        pw_len_ = (pw_hex.size()/2);

        //decode data inputs from hex to binary
        //hex_buffers contain 2x the byte length of original fields
        //we know they will fit in buffers of half their size when decoded back into binary
        hexDecode(account_hex.byteStr(), account_.get(), account_hex.size());
        if (desc_len_ > 0) //description is allowed to be blank
        { hexDecode(desc_hex.byteStr(), description_.get(), desc_hex.size()); }
        hexDecode(uname_hex.byteStr(), username_.get(), uname_hex.size());
        hexDecode(pw_hex.byteStr(), password_.get(), pw_hex.size());
        hexDecode(id_hex.byteStr(), reinterpret_cast<uint8_t*>(id_.data()), id_hex.size());
        hexDecode(hash_hex.byteStr(), reinterpret_cast<uint8_t*>(hash_.data()), hash_hex.size());

        //check if stored hash matches the calculated one IFF this is true then this a valid credential
    }

    #ifdef DBG_CRED
    debugCredential();
    #endif

    if (!isValid()) { throw InvalidDataException{}; }
}

/*****************
* public methods *
******************/
bool credential::isValid() const
{
    const size_t data_size{acnt_len_ + desc_len_ + uname_len_ + pw_len_};
    bool validity{false};

    // credentials with no data are considered invalid
    if (data_size > 0)
    {
        skein_512_hash_t compare{};
        hashCredential(compare);

        validity = (compareWordBuff(hash_.data(), compare.data(), HASH_WORD_SIZE) == 0);
    }

    return validity;
}

bool credential::updateDescription(secStr& description)
{
    return updateField(description, description_, desc_len_);
}

bool credential::updatePassword(secStr& password)
{
    return updateField(password, password_, pw_len_);
}

bool credential::updateUsername(secStr& username)
{
    return updateField(username, username_, uname_len_);
}

secStr credential::getField(const field field)
{
    secStr field_data{};

    //only proceed if the master key is valid and we can generate a derrived key
    if (master_key_.isValid() && derrived_key_.genKey())
    {
        //copy the data from the requested field to a secStr
        switch (field)
        {
            case field::ACCOUNT:
                field_data = secStr{account_.get(), acnt_len_};
            break;
            case field::DESCRIPTION:
                field_data = secStr{description_.get(), desc_len_};
            break;
            case field::USERNAME:
                field_data = secStr{username_.get(), uname_len_};
            break;
            case field::PASSWORD:
                field_data = secStr{password_.get(), pw_len_};
            break;
            case field::INVALID:
            default:
            break;
        }

        // decrypt the field
        decryptValue(field_data.byteStr(), field_data.size(), &derrived_key_);
        // clear the key
        derrived_key_.clearKey();
    }

    // return the data
    return field_data;
}

secStr credential::getAccount()
{
    return getField(field::ACCOUNT);
}

secStr credential::getDescription()
{
    return getField(field::DESCRIPTION);
}

secStr credential::getPassword()
{
    return getField(field::PASSWORD);
}

secStr credential::getUsername()
{
    return getField(field::USERNAME);
}

/*******************
* Stream overloads *
********************/

/* the format streamed out is JSON
* encrypted fields, the salt and binary hashes are dumped as base 16 encoded null
* terminated strings
* as such a buffer of twice the regular string length + 1 must be allocated
* for the hex. hexEncode() DOES NOT do its own memory managment
*/
ostream& operator <<(std::ostream &os, const credential &c)
{
    //start of credential
    os << "{";

    //object (used for parsing)
    os << "\"object\":\"credential\",";

    //account
    if (c.acnt_len_ > 0)
    {
        uint8_t* act_hex = new uint8_t[(2*c.acnt_len_)+1]();
        act_hex[2*c.acnt_len_] = 0; //null terminate the string
        os << "\"account\":\"" << hexEncode(c.account_.get(),
                                            act_hex,
                                            c.acnt_len_)
           << "\",";

        delete[] act_hex; 
        act_hex = 0;
    }
    else { os << "\"account\":\"\","; }

    //description
    if (c.desc_len_ > 0)
    {
        uint8_t* desc_hex = new uint8_t[(2*c.desc_len_)+1]();
        desc_hex[2*c.desc_len_] = 0; //null terminate the string
        os << "\"description\":\"" << hexEncode(c.description_.get(),
                                                desc_hex,
                                                c.desc_len_)
           << "\",";

        delete[] desc_hex;
        desc_hex = 0;
    }
    else { os << "\"description\":\"\","; }

    //username
    if (c.uname_len_ > 0)
    {
        uint8_t* uname_hex = new uint8_t[(2*c.uname_len_)+1]();
        uname_hex[2*c.uname_len_] = 0; //null terminate the string

        os << "\"username\":\"" << hexEncode(c.username_.get(),
                                             uname_hex,
                                             c.uname_len_)
           << "\",";

        delete[] uname_hex;
        uname_hex = 0;
    }
    else { os << "\"username\":\"\","; }

    //password
    if (c.pw_len_ > 0)
    {
        uint8_t* pw_hex = new uint8_t[(2*c.pw_len_)+1]();
        os << "\"password\":\"" << hexEncode(c.password_.get(), pw_hex, c.pw_len_)
           << "\",";

        delete[] pw_hex;
        pw_hex = 0;
    }
    else { os << "\"password\":\"\","; }

    //id
    uint8_t id_hex[(2*HASH_BYTE_SIZE)+1] = { 0 };
    os << "\"id\":\"" << hexEncode(
        reinterpret_cast<uint8_t*>(c.id_.data()),
        id_hex, HASH_BYTE_SIZE)
       << "\",";

    //hash
    uint8_t hash_hex[(2*HASH_BYTE_SIZE)+1] = { 0 };
    os << "\"hash\":\"" << hexEncode((uint8_t*)c.hash_.data(), hash_hex, HASH_BYTE_SIZE)
       << "\",";

    //salt
    uint8_t salt_hex[(2*SALT_BYTE_SIZE)+1] = { 0 };
    os << "\"salt\":\"" << hexEncode(c.derrived_key_.saltBytes(),
                                    salt_hex,
                                    SALT_BYTE_SIZE)
       << "\"";

    //end of credential
    os << "}";

    return os;
}

ostream& operator <<(std::ostream &os, const credential* c)
{
    os << *c; //call the non pointer << operator overload
    return os;
}

/**************
* destructor *
**************/
credential::~credential()
{
    #ifdef DBG_CRED
    array<uint8_t, (2*ID_BYTE_SIZE)+1> id_hex{};
    cout << "Destructor called on credential { " << hexEncode((uint8_t*)id_.data(), id_hex.data(), ID_BYTE_SIZE)
         << " }"<< endl;
    #endif
    //zero fill all buffers that might leak information
    clearBuffer<uint8_t>(account_.get(), acnt_len_);
    clearBuffer<uint8_t>(description_.get(), desc_len_);
    clearBuffer<uint8_t>(password_.get(), pw_len_);
    clearBuffer<uint8_t>(username_.get(), uname_len_);
    acnt_len_ = 0;
    desc_len_ = 0;
    pw_len_ = 0;
    uname_len_ = 0;
    clearArray(hash_);
}

/******************
* private methods *
*******************/

bool credential::decryptValue(uint8_t* value, const size_t byte_size, credentialKey* key)
{
    bool success = false;

    if (value != nullptr && key != NULL)
    {
        //generate the nonce from the salt
        array<key_data_t, CIPHER_WORD_SIZE> nonce{};
        if (skeinHash(
               (uint8_t*)this->derrived_key_.saltBytes(),
               SALT_BYTE_SIZE,
               (uint8_t*)nonce.data(),
               KEY_BYTE_SIZE)
          )
        {
            //decrypt the value
            ctrDecrypt(value, byte_size, nonce.data(), (uint64_t*)derrived_key_.keyBytes());
            success = true;
        }
    }

    return success;
}

bool credential::encryptValue(uint8_t* value, const size_t byte_size, credentialKey* key)
{
    bool success{false};

    if  (value != nullptr && key != NULL)
    {
        //generate the nonce from the derrived key
        array<key_data_t, CIPHER_WORD_SIZE> nonce{};
        if (skeinHash(key->saltBytes(),
                     SALT_BYTE_SIZE,
                     (uint8_t*)nonce.data(),
                     KEY_BYTE_SIZE))
        {
            //ctr encrypt the value
            ctrEncrypt(value, byte_size, nonce.data(), (uint64_t*)derrived_key_.keyBytes());
            success = true;
        }
    }

    return success;
}

inline bool credential::updateField(secStr &new_val, unique_ptr<uint8_t[]> &field, size_t &field_len)
{
    bool success{false};

    if (new_val.size() > 0 &&
        master_key_.isValid() &&
        derrived_key_.genKey())
    {
        //clear the previous field
        if (field_len > 0) { fill(field.get(), field.get()+field_len, 0); }

        field_len = new_val.size();
        //allocate storage and copy the new value into the field
        field = make_unique<uint8_t[]>(new_val.size());
        copy(new_val.byteStr(), (new_val.byteStr()+new_val.size()), field.get());

        //encrypt the new description with the derrived key
        if (!encryptValue(field.get(), field_len, &derrived_key_))
        {
            fill(field.get(), field.get()+field_len, 0);
            field_len = 0;
        }
        else { success = true; } //field succesfully updated

        //clear the derrived key and update the hash
        derrived_key_.clearKey();
        hashCredential(hash_); //update the credential hash
    }

    return success;
}

void credential::hashCredential(skein_512_hash_t &buf) const
{
    SkeinCtx skein_context;
    skeinCtxPrepare(&skein_context, (const SkeinSize_t)SKEIN_SIZE);
    skeinInit(&skein_context, HASH_BIT_SIZE);

    // Changing this will break ABI compatibility
    //Hash all credential data
    skeinUpdate(&skein_context, (uint8_t*)&acnt_len_, sizeof(size_t));
    skeinUpdate(&skein_context, account_.get(), acnt_len_);
    skeinUpdate(&skein_context, (uint8_t*)&desc_len_, sizeof(size_t));
    skeinUpdate(&skein_context, description_.get(), desc_len_);
    skeinUpdate(&skein_context, (uint8_t*)&uname_len_, sizeof(size_t));
    skeinUpdate(&skein_context, username_.get(), uname_len_);
    skeinUpdate(&skein_context, (uint8_t*)&pw_len_, sizeof(size_t));
    skeinUpdate(&skein_context, password_.get(), pw_len_);
    skeinUpdate(&skein_context, derrived_key_.saltBytes(), SALT_BYTE_SIZE);
    skeinFinal(&skein_context, (uint8_t*)buf.data());
}

#ifdef DBG_CRED
void credential::debugCredential() const
{
    //allocate memory
    unique_ptr<uint8_t[]> acnt_hex(new uint8_t[(2*acnt_len_)+1]());
    unique_ptr<uint8_t[]> desc_hex(new uint8_t[(2*desc_len_)+1]());
    unique_ptr<uint8_t[]> uname_hex(new uint8_t[(2*uname_len_)+1]());
    unique_ptr<uint8_t[]> pw_hex(new uint8_t[(2*pw_len_)+1]());
    unique_ptr<uint8_t[]> salt_hex(new uint8_t[(2*SALT_BYTE_SIZE)+1]());
    unique_ptr<uint8_t[]> id_hex(new uint8_t[(2*ID_BYTE_SIZE)+1]());
    unique_ptr<uint8_t[]> hash_hex(new uint8_t[(2*HASH_BYTE_SIZE)+1]());

    //get the original content and hex encode it
    hexEncode(account_.get(), acnt_hex.get(), acnt_len_);
    hexEncode(description_.get(), desc_hex.get(), desc_len_);
    hexEncode(password_.get(), pw_hex.get(), pw_len_);
    hexEncode(username_.get(), uname_hex.get(), uname_len_);
    hexEncode(derrived_key_.saltBytes(), salt_hex.get(), SALT_BYTE_SIZE);
    hexEncode((uint8_t*)id_.data(), id_hex.get(), ID_BYTE_SIZE);
    hexEncode((uint8_t*)hash_.data(), hash_hex.get(), HASH_BYTE_SIZE);

    //print all the info to std out
    cout << "Credential DEBUG:" << endl
              << "{" << endl
              << "\taccount:" << acnt_hex.get() << ":" << acnt_len_ << endl
              << "\tdescription:" << desc_hex.get() << ":" << desc_len_ << endl
              << "\tusername:" << uname_hex.get() << ":" << uname_len_ << endl
              << "\tpassword:" << pw_hex.get() << ":" << pw_len_ << endl
              << "\tsalt:" << salt_hex.get() << ":" << SALT_BYTE_SIZE << endl
              << "\tid:" << id_hex.get() << ":" << ID_BYTE_SIZE << endl
              << "\thash:" << hash_hex.get() << ":" << HASH_BYTE_SIZE << endl
              << "}" << endl << endl;
}
#endif
