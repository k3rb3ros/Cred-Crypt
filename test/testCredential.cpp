#include <array>
#include <gtest/gtest.h>
#include "constants.h"
#include "credential.hpp"
#include "masterKey.hpp"

using std::array;

class CredentialTest : public ::testing::Test
{
    protected:
    masterKey mk{};

    void SetUp() override
    {
        array<key_data_t, KEY_WORD_SIZE> key{7, 6, 5, 4, 3, 2, 1, 0};
        mk.setKey(key.data());
    }
};

TEST_F(CredentialTest, SetUpCreatesValidKey)
{
    ASSERT_TRUE(mk.isSalted());
    ASSERT_TRUE(mk.isValid());
}

TEST_F(CredentialTest, CanConstructCredentialWoutDescription)
{
    secStr acnt{"account"};
    secStr uname{"uname"};
    secStr pw{"pw"};
    credential cred{acnt, uname, pw, mk};
    ASSERT_TRUE(cred.isValid());
}

TEST_F(CredentialTest, CanConstructCredentialWDescription)
{
    secStr acnt{"account"};
    secStr desc{"description"};
    secStr uname{"uname"};
    secStr pw{"pw"};
    credential cred{acnt, desc, uname, pw, mk};
    ASSERT_TRUE(cred.isValid());
}

TEST_F(CredentialTest, CanConstructCredentialWCredentialData)
{
    credentialData data
    {
        secStr{"account"},
        secStr{"description"},
        secStr{"username"},
        secStr{"password"}
    };
    credential cred{data, mk};
    ASSERT_TRUE(cred.isValid());
}

TEST_F(CredentialTest, ExceptionThrownIfMkInvalidAtConstructionTime)
{
    secStr acnt{"account"};
    secStr uname{"uname"};
    secStr pw{"pw"};
    ASSERT_TRUE(mk.isValid());
    mk.clearKey();
    ASSERT_THROW(credential(acnt, uname, pw, mk), InvalidKeyException);
}

TEST_F(CredentialTest, ExceptionThrownIfMkInvalidAtConstructionTime2)
{
    secStr acnt{"account"};
    secStr desc{"description"};
    secStr uname{"uname"};
    secStr pw{"pw"};
    ASSERT_TRUE(mk.isValid());
    mk.clearKey();
    ASSERT_THROW(credential(acnt, desc, uname, pw, mk), InvalidKeyException);
}

TEST_F(CredentialTest, ExceptionThrownIfConstructedFromInvalidData)
{
    // all of this data is invalid
    secStr acnt{"account"};
    secStr desc{"desc"};
    secStr uname{"username"};
    secStr pw{"password"};
    secStr id{"id1234"};
    secStr hash{"hash00"};
    secStr salt{"salt00"};
    ASSERT_THROW(credential(acnt, desc, uname, pw, id, hash, salt, mk),
                 InvalidDataException);
}

TEST_F(CredentialTest, CredentialWithNoDataThrowsExceptoinWhenConstructed1)
{
    secStr acnt{""};
    secStr uname{""};
    secStr pw{""};
    ASSERT_THROW(credential(acnt, uname, pw, mk), InvalidDataException);
}

TEST_F(CredentialTest, CredentialWithNoDataThrowsExceptoinWhenConstructed2)
{
    secStr acnt{""};
    secStr desc{""};
    secStr uname{""};
    secStr pw{""};
    ASSERT_THROW(credential(acnt, desc, uname, pw, mk), InvalidDataException);
}

TEST_F(CredentialTest, GetIdentifierWorks)
{
    secStr acnt{"account"};
    secStr uname{"username"};
    secStr pw{"password"};
    credential cred{acnt, uname, pw, mk};

    // identifiers are keyed off of account
    const auto id = cred.getIdentifier();
    const identifier id_compare{acnt};
    ASSERT_TRUE(id == identifier{acnt});
}

TEST_F(CredentialTest, GetDescriptionReturnsDescriptionWhenKeyValid)
{
    secStr acnt{"account"};
    secStr desc{"description"};
    secStr uname{"username"};
    secStr pw{"password"};
    credential cred{acnt, desc, uname, pw, mk};

    auto cred_desc = cred.getDescription();
    ASSERT_TRUE(cred_desc == desc);
}

TEST_F(CredentialTest, GetDescriptionReturnsEmptyStringWhenKeyInvalid)
{
    secStr acnt{"account"};
    secStr desc{"description"};
    secStr uname{"username"};
    secStr pw{"password"};
    credential cred{acnt, desc, uname, pw, mk};
    secStr empty{};

    mk.clearKey();
    auto cred_desc = cred.getDescription();
    ASSERT_TRUE(cred_desc == empty);
}

TEST_F(CredentialTest, GetUsernameReturnsUsernameWhenKeyValid)
{
    secStr acnt{"account"};
    secStr desc{"description"};
    secStr uname{"username"};
    secStr pw{"password"};
    credential cred{acnt, desc, uname, pw, mk};

    auto cred_uname = cred.getUsername();
    ASSERT_TRUE(cred_uname == uname);
}

TEST_F(CredentialTest, GetUsernameReturnsEmptyStringWhenKeyInvalid)
{
    secStr acnt{"account"};
    secStr desc{"description"};
    secStr uname{"username"};
    secStr pw{"password"};
    credential cred{acnt, desc, uname, pw, mk};
    secStr empty{};

    mk.clearKey();
    auto cred_uname = cred.getUsername();
    ASSERT_TRUE(cred_uname == empty);
}

TEST_F(CredentialTest, GetPasswordReturnsPasswordWhenKeyValid)
{
    secStr acnt{"account"};
    secStr desc{"description"};
    secStr uname{"username"};
    secStr pw{"password"};
    credential cred{acnt, desc, uname, pw, mk};

    auto cred_pw = cred.getPassword();
    ASSERT_TRUE(cred_pw == pw);
}

TEST_F(CredentialTest, GetPasswordReturnEmptyStringWhenKeyInvalid)
{
    secStr acnt{"account"};
    secStr desc{"description"};
    secStr uname{"username"};
    secStr pw{"password"};
    credential cred{acnt, desc, uname, pw, mk};
    secStr empty{};

    mk.clearKey();
    auto cred_pw = cred.getPassword();
    ASSERT_TRUE(cred_pw == empty);
}
