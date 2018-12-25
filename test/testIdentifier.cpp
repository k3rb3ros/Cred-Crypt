#include <identifier.hpp>
#include <gtest/gtest.h>
#include <secureString.hpp>

class identifierTest : public ::testing::Test
{
    public:
    static void ids_equal(const id_data_t* lhs, const id_data_t* rhs)
    {
        ASSERT_TRUE(memcmp(lhs, rhs, ID_BYTE_SIZE) == 0);
    }
};

TEST(identifierTest, DefaultIdIsAllZeroed)
{
    identifier id{};
    identifier_t empty{};
    identifierTest::ids_equal(id.data(), empty.data());
}

TEST(identifierTest, EqualityCompareReturnsTrueForEqualIds)
{
    identifier lhs{};
    identifier rhs{};

    ASSERT_EQ(lhs, rhs);
}

TEST(identifierTest, EqualityCompareReturnsFalseForEqualIds)
{
    identifier lhs{};
    auto lhs_data = lhs.data();
    lhs_data[7] = 0x42;
    identifier rhs{};

    ASSERT_FALSE(lhs == rhs);
}

TEST(identifierTest, ConstEqualityOperatorReturnTrueForEqualIds)
{
    const identifier lhs{};
    const identifier rhs{};

    ASSERT_EQ(lhs, rhs);
}

TEST(identifierTest, ConstEqualityOperatorReturnsFalseForUnEqualIds)
{
    const identifier lhs{};
    const identifier rhs{};
    auto rhs_data = rhs.data();
    rhs_data[7] = 13;

    ASSERT_FALSE(lhs == rhs);
}

TEST(identifierTest, GreaterThanOperatorReturnTrueWhenLhsGreaterThanRhs)
{
    identifier lhs{};
    lhs.data()[3] = 0x1300;
    identifier rhs{};
    // this is after the first difference in value so lhs should evaluate to greater than rhs
    rhs.data()[4] = 0x2600;

    ASSERT_TRUE(lhs > rhs);
}

TEST(identifierTest, GreaterThanOperatorReturnsFalseWhenLhsNotGreaterThanRhs)
{
    // comparisons are done from [0] - [7] moving up in array indexes only when the previous indexes are equal
    identifier lhs{};
    lhs.data()[0] = 0x69;
    identifier rhs{};
    rhs.data()[0] = 0x69;
    rhs.data()[7] = 0x1;

    ASSERT_FALSE(lhs > rhs);
}

TEST(identifierTest, GreaterThanOperatorReturnsFalseWhenLhsEqualToRhs)
{
    identifier lhs{};
    lhs.data()[0] = 0x42;
    lhs.data()[3] = 0x13;
    lhs.data()[7] = 0x54;
    identifier rhs{};
    rhs.data()[0] = 0x42;
    rhs.data()[3] = 0x13;
    rhs.data()[7] = 0x54;

    ASSERT_FALSE(lhs > rhs);
}

TEST(identifierTest, ConstLessThanOperatorReturnsTrueWhenLhsLessThanRhs)
{
    const identifier lhs{};
    lhs.data()[0] = 0x94;
    lhs.data()[7] = 0x13;
    const identifier rhs{};
    rhs.data()[0] = 0x94;
    rhs.data()[7] = 0x29;

    ASSERT_TRUE(lhs < rhs);
}

TEST(identifierTest, ConstLessThanOperatorReturnsFalsWhenLhsEqualToRhs)
{
    const identifier lhs{};
    lhs.data()[7] = 0x61;
    const identifier rhs{};
    rhs.data()[7] = 0x61;

    ASSERT_FALSE(lhs < rhs);
}

TEST(identifierTest, ConstLessThanOperatorReturnsFalseWhenLhsGtRhs)
{
    const identifier lhs{};
    lhs.data()[7] = 0x69;
    const identifier rhs{};
    rhs.data()[7] = 0x61;

    ASSERT_FALSE(lhs < rhs);
}

TEST(identifierTest, LessThanOperatorReturnsTrueWhenLhsLessThanRhs)
{
    identifier lhs{};
    lhs.data()[4] = 0x94;
    lhs.data()[7] = 0x03;
    identifier rhs{};
    rhs.data()[4] = 0x94;
    rhs.data()[7] = 0x13;

    ASSERT_TRUE(lhs < rhs);
}

TEST(identifierTest, LessThanOperatorReturnsFalseWhenLhsEqualToRhs)
{
    identifier lhs{};
    lhs.data()[0] = 0x94;
    lhs.data()[7] = 0x13;
    identifier rhs{};
    rhs.data()[0] = 0x94;
    rhs.data()[7] = 0x13;

    ASSERT_FALSE(lhs < rhs);
}

TEST(identifierTest, LessThanOperatorReturnsFalseWhenLhsGtRhs)
{
    identifier lhs{};
    lhs.data()[0] = 0x94;
    lhs.data()[7] = 0x31;
    identifier rhs{};
    rhs.data()[0] = 0x94;
    rhs.data()[7] = 0x13;

    ASSERT_FALSE(lhs < rhs);
}
