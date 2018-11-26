#include <algorithm>
#include <array>
#include <cstring>
#include <gtest/gtest.h>
#include <secureString.hpp>
#include <type_traits>
#include "exceptions.hpp"
#include "masterKey.hpp"

using std::array;
using std::equal;

class masterKeyTest : public ::testing::Test
{
};

TEST(masterKeyTest, DefaultConstructedMasterKeyIsSalted)
{
    masterKey mk{};
    ASSERT_TRUE(mk.isSalted());
}

TEST(masterKeyTest, DefaultConstructedMasterKeyIsNotKeyed)
{
    masterKey mk{};
    ASSERT_FALSE(mk.isKeyed());
}

TEST(masterKeyTest, DefaultConstructedMasterKeyIsNotValid)
{
    masterKey mk{};
    ASSERT_FALSE(mk.isValid());
}

TEST(masterKeyTest, CanConstructMasterKeyWithSaltHex)
{
    secStr salt_hex{"ffffffffffffffff"};
    masterKey mk{salt_hex};

    ASSERT_TRUE(mk.isSalted());
}

TEST(masterKeyTest, InvalidSaltHexThrowsException)
{
    secStr invalid_hex{"not_a_hex"};
    ASSERT_THROW(masterKey{invalid_hex}, InvalidSaltHexException);
}

TEST(masterKeyTest, CanSetSalt)
{
    masterKey mk{};
    array<key_data_t, 8> salt{0, 1, 2, 3, 4, 5, 6, 7};

    mk.clearSalt();
    ASSERT_FALSE(mk.isSalted());
    mk.setSalt(salt.data());
    ASSERT_TRUE(mk.isSalted());
    auto salt_bytes{mk.saltBytes()};
    ASSERT_TRUE(equal(salt_bytes, salt_bytes+mk.byteSize(), (uint8_t*)salt.data()));
}

TEST(masterKeyTest, CanClearSalt)
{
    masterKey mk{};
    array<key_data_t, 8> salt{0, 1, 2, 3, 4, 5, 6, 7};
    mk.setSalt(salt.data());

    ASSERT_TRUE(mk.isSalted());
    mk.clearSalt();
    ASSERT_FALSE(mk.isSalted());
}

TEST(masterKeyTest, CanSetKey)
{
    masterKey mk{};
    array<key_data_t, 8> key{0, 1, 2, 3, 4, 5, 6, 7};
    mk.setKey(key.data());

    ASSERT_TRUE(mk.isKeyed());
    auto key_data{mk.keyData()};
    ASSERT_TRUE(equal(key_data, key_data+mk.dataSize(), key.data()));
}

TEST(masterKeyTest, CanClearKey)
{
    masterKey mk{};
    array<key_data_t, 8> empty{};
    array<key_data_t, 8> key{0, 1, 2, 3, 4, 5, 6, 7};
    mk.setKey(key.data());

    ASSERT_TRUE(mk.isKeyed());
    mk.clearKey();
    ASSERT_FALSE(mk.isKeyed());
    auto raw_key = mk.keyData();
    ASSERT_TRUE(equal(raw_key, raw_key+mk.dataSize(), empty.data()));
}

TEST(masterKeyTest, IsValidReturnsTrueWhenSaltAndKeyAreNonZero)
{
    array<key_data_t, 8> salt{0, 1, 2, 3, 4, 5, 6, 7};
    array<key_data_t, 8> key{7, 6, 5, 4, 3, 2, 1, 0};
    masterKey mk{};
    mk.setSalt(salt.data());
    mk.setKey(key.data());
    ASSERT_TRUE(mk.isValid());
}

TEST(masterKeyTest, InputPasswordFailsWhenUnsalted)
{
    masterKey mk{};
    secStr pw{"password1234"};
    mk.clearSalt();
    ASSERT_FALSE(mk.inputPassword(pw));
}

TEST(masterKeyTest, InputPasswordGeneratesKeyWhenSalted)
{
    secStr pw{"password1234"};
    secStr salt_hex{"0001020304050607"};
    masterKey mk{salt_hex};
    ASSERT_TRUE(mk.inputPassword(pw));
    ASSERT_TRUE(mk.isKeyed());
    ASSERT_TRUE(mk.isValid());
}

TEST(masterKeyTest, CanGetKeyAsKeyDataTPtr)
{
    array<key_data_t, 8> salt{0, 1, 2, 3, 4, 5, 6, 7};
    array<key_data_t, 8> key{7, 6, 5, 4, 3, 2, 1, 0};
    masterKey mk{};
    mk.setSalt(salt.data());
    mk.setKey(key.data());
    ASSERT_EQ((key_data_t*)mk.keyBytes(), mk.keyData());
    ASSERT_STREQ("PKm", typeid(mk.keyData()).name());
}
