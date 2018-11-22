#include <gtest/gtest.h>
#include "masterKey.hpp"

class masterKeyTest : public ::testing::Test
{
};

TEST(masterKeyTest, DefaultConstructedMasterKeyIsNotSalted)
{
    masterKey mk{};
    ASSERT_FALSE(mk.isSalted());
}

TEST(masterKeyTest, DefaultConstructedMasterKeyIsNotKeyed)
{
    masterKey mk{};
    ASSERT_FALSE(mk.isSalted());
}

TEST(masterKeyTest, DefaultConstructedMasterKeyIsNotValid)
{
    masterKey mk{};
    ASSERT_FALSE(mk.isValid());
}
