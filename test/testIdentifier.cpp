#include <identifier.hpp>
#include <gtest/gtest.h>
#include <secureString.hpp>

class masterKeyTest : public ::testing::Test
{
    public:
    static void ids_equal(const id_data_t* lhs, const id_data_t* rhs)
    {
        ASSERT_TRUE(memcmp(lhs, rhs, ID_BYTE_SIZE) == 0);
    }
};

TEST(masterKeyTest, DefaultIdIsAllZeroed)
{
    identifier id{};
    identifier_t empty{};
    masterKeyTest::ids_equal(id.data(), empty.data());
}
