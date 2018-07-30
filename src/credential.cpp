#include "include/credential.hpp"

/***************
* constructors *
****************/
credential::credential(secStr& account,
                       secStr& username,
                       secStr& password,
                       const masterKey* master_key
                      ): master_key_(master_key), derrived_key_(master_key_),
                         account_(new uint8_t[account.size()]()),
                         description_(nullptr),
                         username_(new uint8_t[username.size()]()),
                         password_(new uint8_t[password.size()]())
{

    //set the lengths for account, description, password, username
    acnt_length_ = account.size();
    desc_length_ = 0;
    uname_length_ = username.size();
    pw_length_ = password.size();

    if (acnt_length_ > 0 && uname_length_ > 0 && pw_length_ > 0)
    {
        //generate the salt and in turn the derrived key   
        if (master_key_->isValid())
        {
            if (derrived_key_.isValid())
            {
                //copy the data into the credential
                memcpy(account_.get(), account.byteStr(), acnt_length_);
                memcpy(username_.get(), username.byteStr(), uname_length_);
                memcpy(password_.get(), password.byteStr(), pw_length_);

                //encrypt the data
                encryptValue(account_.get(), acnt_length_, &derrived_key_);
                encryptValue(username_.get(), uname_length_, &derrived_key_);
                encryptValue(password_.get(), pw_length_, &derrived_key_);

                derrived_key_.clearKey(); //clear the derrived key
                hashCredential(hash_); //update the credential hash
                genId(account); //generate the id
            }
        }
    }

    #ifdef DBG_CRED
    debugCredential();
    #endif
}

credential::credential(secStr& account,
                       secStr& description,
                       secStr& username,
                       secStr& password,
                       const masterKey* master_key
                      ): master_key_(master_key), derrived_key_(master_key_),
                         account_(new uint8_t[account.size()]()),
                         description_(new uint8_t[description.size()]()),
                         username_(new uint8_t[username.size()]()),
                         password_(new uint8_t[password.size()]())
{
    //set the lengths of the stored text fields
    acnt_length_ = account.size();
    desc_length_ = description.size();
    pw_length_ = password.size();
    uname_length_ = username.size();

    if (acnt_length_ > 0 && desc_length_ > 0 &&
        pw_length_ > 0 && uname_length_ > 0)
    {
        if (master_key_->isValid())
        {
            if (derrived_key_.isValid())
            {
                //copy data into the credential
                memcpy(account_.get(), account.byteStr(), acnt_length_);
                memcpy(description_.get(), description.byteStr(), desc_length_);
                memcpy(username_.get(), username.byteStr(), uname_length_);
                memcpy(password_.get(), password.byteStr(), pw_length_);

                //encrypt the data
                encryptValue(account_.get(), acnt_length_, &derrived_key_);
                encryptValue(description_.get(), desc_length_, &derrived_key_);
                encryptValue(password_.get(), pw_length_, &derrived_key_);
                encryptValue(username_.get(), uname_length_, &derrived_key_);
            
                derrived_key_.clearKey(); //clear the key
                hashCredential(hash_); //update the credential hash
                genId(account); //generate the the id
            }
        }
    }

    #ifdef DBG_CRED
    debugCredential();
    #endif
}

//persistent credential constructor 
credential::credential(secStr& account_hex,
                       secStr& desc_hex,
                       secStr& uname_hex,
                       secStr& pw_hex,
                       secStr& id_hex,
                       secStr& hash_hex,
                       secStr& salt_hex,
                       const masterKey* master_key
                      ): master_key_(master_key),
                         derrived_key_(master_key_, salt_hex),
                         account_(new uint8_t[account_hex.size()/2]()),
                         description_(new uint8_t[desc_hex.size()/2]()),
                         username_(new uint8_t[uname_hex.size()/2]()),
                         password_(new uint8_t[pw_hex.size()/2]())
{
    if (account_hex.size() > 0 && (account_hex.size() % 2) == 0 &&
        uname_hex.size() > 0 && (uname_hex.size() % 2) == 0 &&
        pw_hex.size() > 0 && (pw_hex.size() % 2) == 0 &&
        id_hex.size() > 0 && (id_hex.size() % 2) == 0 &&
        salt_hex.size() > 0 && (salt_hex.size() % 2) == 0 &&
        hash_hex.size() > 0 && (hash_hex.size() % 2) == 0
       )
    {     
        //set the lengths of the stored text fields
        acnt_length_ = (account_hex.size()/2);
        desc_length_ = (desc_hex.size()/2);
        uname_length_ = (uname_hex.size()/2);
        pw_length_ = (pw_hex.size()/2);

        clearBuff((uint8_t*)hash_, HASH_BYTE_SIZE);

        //decode data inputs from hex to binary
        //hex_buffers contain 2x the byte length of original fields
        //we know they will fit in buffers of half their size when decoded back into binary
        hexDecode(account_hex.byteStr(), account_.get(), account_hex.size());
        if (desc_length_ > 0) //description is allowed to be blank
        { hexDecode(desc_hex.byteStr(), description_.get(), desc_hex.size()); }
        hexDecode(uname_hex.byteStr(), username_.get(), uname_hex.size());
        hexDecode(pw_hex.byteStr(), password_.get(), pw_hex.size());
        hexDecode(id_hex.byteStr(), reinterpret_cast<uint8_t*>(id_.getID()), id_hex.size());
        hexDecode(hash_hex.byteStr(), (uint8_t*)hash_, hash_hex.size());

        //check if stored hash matches the calculated one IFF this is true then this a valid credential
    }
    
    #ifdef DBG_CRED
    debugCredential();
    #endif
}

/*****************
* public methods *
******************/
bool credential::isKeyed() const
{
    return derrived_key_.isValid();
}

bool credential::isValid()
{
    uint64_t hash_cmp[HASH_WORD_SIZE] = { 0 };
    hashCredential(hash_cmp);

    return (compareWordBuff(hash_, hash_cmp, HASH_WORD_SIZE) == 0);
}

bool credential::updateDescription(secStr& description)
{
    return updateField(description, description_, desc_length_);
}

bool credential::updatePassword(secStr& password)
{
    return updateField(password, password_, pw_length_);
}

bool credential::updateUsername(secStr& username)
{
    return updateField(username, username_, uname_length_);
}

inline uint8_t* credential::getField(unique_ptr<uint8_t[]> &field, size_t &field_len)
{
    uint8_t* decrypted_field = nullptr;

    //check that we can generate the derrived key generate it if we can
    if (master_key_->isValid() && derrived_key_.genKey())
    {
        decrypted_field = new uint8_t[field_len]();

        //copy the field to a new buffer and perform the decryption
        if (decrypted_field != nullptr &&
            memcpy(decrypted_field, field.get(), field_len) != nullptr &&
            decryptValue(decrypted_field, field_len, &derrived_key_) == false)
        {
            //clean up our resource on failure
            clearBuff(decrypted_field, field_len);
            delete[] decrypted_field;
            decrypted_field = nullptr;
        }
       derrived_key_.clearKey(); //clear the key
    }

    return decrypted_field;
}

secStr credential::getAccountStr()
{
    uint8_t* acnt = getField(account_, acnt_length_); //get the account
    secStr Acnt = (acnt != nullptr) ? secStr(acnt, acnt_length_) : secStr();

    if (acnt != nullptr)
    {
        delete[] acnt;
        acnt = nullptr;
    }

    return Acnt;
}

secStr credential::getDescriptionStr()
{
    uint8_t* desc = getField(description_, desc_length_); //get the description
    secStr Desc = (desc != nullptr) ? secStr(desc, desc_length_) : secStr();

    if (desc != nullptr)
    {
        clearBuff(desc, desc_length_);
        delete[] desc;
        desc = nullptr;
    }

    return Desc;
}

secStr credential::getPasswordStr()
{
    uint8_t* pw = getField(password_, pw_length_); //get the password
    secStr Pw = (pw != nullptr) ? secStr(pw, pw_length_) : secStr();

    if (pw != nullptr)
    {
        clearBuff(pw, pw_length_);
        delete[] pw;
        pw = nullptr;
    }

    return Pw;
}

secStr credential::getUsernameStr()
{
    uint8_t* uname = getField(username_, uname_length_); //get the username
    secStr Uname = (uname != nullptr) ? secStr(uname, uname_length_) : secStr();

    if (uname != nullptr)
    {
        clearBuff(uname, uname_length_);
        delete[] uname;
        uname = nullptr;
    }

    return Uname;
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
    if (c.acnt_length_ > 0)
    {
        uint8_t* act_hex = new uint8_t[(2*c.acnt_length_)+1]();
        act_hex[2*c.acnt_length_] = 0; //null terminate the string
        os << "\"account\":\"" << hexEncode(c.account_.get(),
                                            act_hex,
                                            c.acnt_length_) 
           << "\",";

        delete[] act_hex; 
        act_hex = 0;
    }
    else { os << "\"account\":\"\","; }

    //description
    if (c.desc_length_ > 0)
    {
        uint8_t* desc_hex = new uint8_t[(2*c.desc_length_)+1]();
        desc_hex[2*c.desc_length_] = 0; //null terminate the string
        os << "\"description\":\"" << hexEncode(c.description_.get(),
                                                desc_hex,
                                                c.desc_length_)
           << "\",";

        delete[] desc_hex;
        desc_hex = 0;
    }
    else { os << "\"description\":\"\","; }

    //username
    if (c.uname_length_ > 0)
    {
        uint8_t* uname_hex = new uint8_t[(2*c.uname_length_)+1]();
        uname_hex[2*c.uname_length_] = 0; //null terminate the string

        os << "\"username\":\"" << hexEncode(c.username_.get(),
                                             uname_hex,
                                             c.uname_length_)
           << "\",";

        delete[] uname_hex;
        uname_hex = 0;
    }
    else { os << "\"username\":\"\","; }

    //password
    if (c.pw_length_ > 0)
    {
        uint8_t* pw_hex = new uint8_t[(2*c.pw_length_)+1]();
        os << "\"password\":\"" << hexEncode(c.password_.get(), pw_hex, c.pw_length_)
           << "\",";

        delete[] pw_hex;
        pw_hex = 0;
    }
    else { os << "\"password\":\"\","; }

    //id
    uint8_t id_hex[(2*HASH_BYTE_SIZE)+1] = { 0 };
    os << "\"id\":\"" << hexEncode(
        reinterpret_cast<uint8_t*>(c.id_.getID()),
        id_hex, HASH_BYTE_SIZE)
       << "\",";

    //hash 
    uint8_t hash_hex[(2*HASH_BYTE_SIZE)+1] = { 0 };
    os << "\"hash\":\"" << hexEncode((uint8_t*)c.hash_, hash_hex, HASH_BYTE_SIZE)
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
    uniqe_ptr<uint8_t*> id_hex(new uint8_t[2*ID_BYTE_SIZE+1]());
    cout << "Destructor called on credential { " << hexEncode((uint8_t*)id_, id_hex, ID_BYTE_SIZE)
         << " }"<< endl;
    #endif
    //delete the derrived key and set the reference to the master key to null

    //derrived_key DTOR zero fills all sensative content on destruction so we don't need to
    master_key_ = nullptr; //credential does not own masterKey so we don't free it

    //zero fill all buffers that might leak information
    clearBuff(account_.get(), acnt_length_);
    clearBuff(description_.get(), desc_length_);
    clearBuff(password_.get(), pw_length_);
    clearBuff(username_.get(), uname_length_);
    clearBuff((uint8_t*)hash_, HASH_BYTE_SIZE);

    acnt_length_ = 0;
    desc_length_ = 0;
    pw_length_ = 0;
    uname_length_ = 0;
}

/******************
* private methods *
*******************/ 
bool credential::checkHash()
{
    bool hash_match = true;
    skein_hash test_hash = { 0 };

    hashCredential(test_hash);

    for (size_t sz=0; sz < HASH_WORD_SIZE; ++sz)
    {
        if (hash_[sz] != test_hash[sz])
        {
            hash_match = false;
            break;
        }
    }

    return hash_match;
}

bool credential::decryptValue(uint8_t* value, const size_t byte_size, credentialKey* key)
{
    bool success = false;

    if (value != nullptr && key != NULL)
    {
        //generate the nonce from the salt
        uint64_t nonce[CIPHER_WORD_SIZE] = { 0 };
        if (skeinHash((uint8_t*)this->derrived_key_.saltBytes(),
                     SALT_BYTE_SIZE,
                     (uint8_t*)nonce,
                     KEY_BYTE_SIZE)
          )
        {
            //decrypt the value
            ctrDecrypt(value, byte_size, (uint64_t*)nonce, (uint64_t*)derrived_key_.keyBytes());
            success = true;
        }
    }

    return success;
}

bool credential::encryptValue(uint8_t* value, const size_t byte_size, credentialKey* key)
{
    bool success = false;

    if  (value != nullptr && key != NULL)
    {
        //generate the nonce from the derrived key
        uint64_t nonce[CIPHER_WORD_SIZE] = { 0 };
        if (skeinHash(key->saltBytes(),
                     SALT_BYTE_SIZE,
                     (uint8_t*)nonce,
                     KEY_BYTE_SIZE))
        {
            //ctr encrypt the value
            ctrEncrypt(value, byte_size, (uint64_t*)nonce, (uint64_t*)derrived_key_.keyBytes());
            success = true;
        }
    }

    return success;
}

bool credential::genId(secStr& account)
{
    bool success = false;

    if (account.size() > 0)
    {

        if (skeinHash(
              account.byteStr(),
              account.size(), 
              reinterpret_cast<uint8_t*>(id_.getID()),
              (ID_BYTE_SIZE)))
        {
            success = true;
        }
    }

    return success;
}

inline bool credential::updateField(secStr &new_val, unique_ptr<uint8_t[]> &field, size_t &field_len)
{
    bool success = false;

    if (new_val.size() > 0 &&
        master_key_->isValid() &&
        derrived_key_.genKey())
    {
        //clear the existing password
        if (field_len > 0) { clearBuff(field.get(), field_len); }

        field_len = new_val.size();
        //allocate storage and copy the new field into it
        field = unique_ptr<uint8_t[]>(new uint8_t [field_len]());
        memcpy(field.get(), new_val.byteStr(), field_len);

        //encrypt the new description with the derrived key
        if (!encryptValue(field.get(), field_len, &derrived_key_))
        {
            clearBuff(field.get(), field_len);
            field_len = 0;
        }
        else { success = true; } //field succesfully updated

        //clear the derrived key and update the hash
        derrived_key_.clearKey();
        hashCredential(hash_); //update the credential hash
    }

    return success;
}

void credential::hashCredential(skein_hash &buf)
{
    struct SkeinCtx skein_context;
    skeinCtxPrepare(&skein_context, (const SkeinSize_t)SKEIN_SIZE);
    skeinInit(&skein_context, HASH_BIT_SIZE);

    //Hash all credential data
    skeinUpdate(&skein_context, (uint8_t*)&acnt_length_, sizeof(size_t));
    skeinUpdate(&skein_context, account_.get(), acnt_length_);
    skeinUpdate(&skein_context, (uint8_t*)&desc_length_, sizeof(size_t));
    skeinUpdate(&skein_context, description_.get(), desc_length_);
    skeinUpdate(&skein_context, (uint8_t*)&uname_length_, sizeof(size_t));
    skeinUpdate(&skein_context, username_.get(), uname_length_);
    skeinUpdate(&skein_context, (uint8_t*)&pw_length_, sizeof(size_t));
    skeinUpdate(&skein_context, password_.get(), pw_length_);
    skeinUpdate(&skein_context, derrived_key_.saltBytes(), SALT_BYTE_SIZE);
    skeinFinal(&skein_context, (uint8_t*)buf);
}

#ifdef DBG_CRED
void credential::debugCredential() const
{
    //allocate memory
    unique_ptr<uint8_t[]> acnt_hex(new uint8_t[(2*acnt_length_)+1]());
    unique_ptr<uint8_t[]> desc_hex(new uint8_t[(2*desc_length_)+1]());
    unique_ptr<uint8_t[]> uname_hex(new uint8_t[(2*uname_length_)+1]());
    unique_ptr<uint8_t[]> pw_hex(new uint8_t[(2*pw_length_)+1]());
    unique_ptr<uint8_t[]> salt_hex(new uint8_t[(2*SALT_BYTE_SIZE)+1]());
    unique_ptr<uint8_t[]> id_hex(new uint8_t[(2*ID_BYTE_SIZE)+1]());
    unique_ptr<uint8_t[]> hash_hex(new uint8_t[(2*HASH_BYTE_SIZE)+1]());

    //get the original content and hex encode it
    hexEncode(account_, acnt_hex, acnt_length_);
    hexEncode(description_, desc_hex, desc_length_);
    hexEncode(password_, pw_hex, pw_length_);
    hexEncode(username_, uname_hex, uname_length_);
    hexEncode(derrived_key_.saltBytes(), salt_hex, SALT_BYTE_SIZE);
    hexEncode((uint8_t*)id_, id_hex, ID_BYTE_SIZE);
    hexEncode((uint8_t*)hash_, hash_hex, HASH_BYTE_SIZE);

    //print all the info to std out
    cout << "Credential DEBUG:" << endl
              << "{" << endl
              << "\taccount:" << acnt_hex << ":" << acnt_length_ << endl
              << "\tdescription:" << desc_hex << ":" << desc_length_ << endl
              << "\tusername:" << uname_hex << ":" << uname_length_ << endl
              << "\tpassword:" << pw_hex << ":" << pw_length_ << endl
              << "\tsalt:" << salt_hex << ":" << SALT_BYTE_SIZE << endl
              << "\tid:" << id_hex << ":" << ID_BYTE_SIZE << endl
              << "\thash:" << hash_hex << ":" << HASH_BYTE_SIZE << endl
              << "}" << endl << endl;
}
#endif
