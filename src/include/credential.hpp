/*
* A credential is an abstraction for everything that is necessary to log on or
* authenticate to a service. It stores
* Account the name of the account being authenticated to.
* Description any optional information that might be relevant to authenticate to* the account.
* Username the username needed to authenticate the account.
* Password the password needed to authenticate to the account.
* All credential information is stored in an encrypted form so a memory dump of the running program won't reveal any sensative account information.
* Account, Description, Password, Username are encrypted with CTR_THREEFISH_512
* The low level credential key is made by xoring the credential salt with the master key
* The password is protected by the high level credential key which is generated
* by stretching the low level key through the scrypt key derrivation function.
* credential keys are not stored instead they are generated as needed and only live
* as long as the scope of the credential operation requireing that key
*/

#pragma once

#include <algorithm> //std::copy //std::fill
#include <array> //std::array
#include <cstdio> //size_t
#include <cstdint> //uintxx_t types
#include <iostream> //std::ofstream object
#include <memory> //std::unique_ptr
#include "constants.h" //ID_WORD_SIZE, ID_BYTE_SIZE
#include "credentialData.hpp" //credentialData class
#include "credentialKey.hpp" //credentialKey class
#include "identifier.hpp" //identifier class
#include "masterKey.hpp" //masterKey class
#include "secureString.hpp" //secStr (secureString) class

using skein_512_hash_t = std::array<uint64_t, HASH_WORD_SIZE>;

enum class field: uint_fast8_t
{
    INVALID,
    ACCOUNT,
    DESCRIPTION,
    PASSWORD,
    USERNAME
};

class credential
{
    public:
    /***************
    * constructors *
    ****************/
    credential() = delete;

    // descriptions are optional so we allow construction without one
    explicit credential(secStr& account,
                        secStr& username,
                        secStr& password,
                        const masterKey& master_key);

    explicit credential(secStr& account,
                        secStr& description,
                        secStr& username,
                        secStr& password,
                        const masterKey& master_key);

    // calls above constructor
    explicit credential(credentialData& raw_cred, const masterKey& master_key);

    /*imported from existing (values already encrypted)*/
    explicit credential(secStr& account_hex,
                        secStr& desc_hex,
                        secStr& uname_hex,
                        secStr& pw_hex,
                        secStr& id_hex,
                        secStr& hash_hex,
                        secStr& salt_hex,
                        const masterKey& master_key);

    /*****************
    * public methods *
    ******************/
    bool isValid() const;
    bool updateDescription(secStr& description);
    bool updatePassword(secStr& password);
    bool updateUsername(secStr& username);

    const identifier& getIdentifier() const { return id_; };

    secStr getAccount();
    secStr getDescription();
    secStr getPassword();
    secStr getUsername();

    /***********************
    * Comparison overloads *
    ************************/
    inline bool operator ==(credential &rhs) const { return id_ == rhs.id_; }
    inline bool operator <(credential &rhs) const { return id_ < rhs.id_; }
    inline bool operator >(credential &rhs) const { return id_ > rhs.id_; }

    /**************************
    * Serialization overloads *
    **************************/
    friend ostream& operator <<(ostream &os, const credential &cred);
    friend ostream& operator <<(ostream &os, const credential* cred);

    /*************
    * destructor *
    **************/
    ~credential();

    private:
    /***************
    * private data *
    ****************/
    skein_512_hash_t hash_{};
    identifier id_{};
    size_t acnt_len_{0};
    size_t desc_len_{0};
    size_t uname_len_{0};
    size_t pw_len_{0};
    unique_ptr<uint8_t[]> account_{nullptr};
    unique_ptr<uint8_t[]> description_{nullptr};
    unique_ptr<uint8_t[]> username_{nullptr};
    unique_ptr<uint8_t[]> password_{nullptr};
    const masterKey& master_key_;
    credentialKey derrived_key_;

    /******************
    * private methods *
    *******************/

    /*
    * return true if the calculated hash matches the stored hash
    */
    bool checkHash() const;

    /*********************************************************************
     * The Crypto methods have no awareness if the key is correct or not *
     *********************************************************************/
    /*
     * decrypt the given value returns true if the operation succeeded
     */
    bool decryptValue(uint8_t* value, const size_t byte_size, credentialKey* key);

    /*
     * encrypt the given value returns true if the operation succeeded
     */
    bool encryptValue(uint8_t* value, const size_t byte_size, credentialKey* key);

    /* Generic update reduces code duplication*/
    bool updateField(secStr &new_val,
                     unique_ptr<uint8_t[]> &field,
                     size_t &field_len);

    /*
    * populates the passed in secStr with the selected Field or nothing if the key is invalid
    */
    secStr getField(const field field);

    #ifdef DBG_CRED
    /*
    * Print the hex encoding off all fields in a credential to stdout for
    * debugging purposes.
    */
    void debugCredential() const;
    #endif

    /*
    * Get the Skein hash of accout, description, password and username
    */
    void hashCredential(skein_512_hash_t &buf) const;
};
