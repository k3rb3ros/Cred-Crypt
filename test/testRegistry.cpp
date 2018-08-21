#include "include/testRegistry.hpp"

using std::make_unique;

TEST(unitTestRegistry, DefaultRegistryIsEmpty)
{
    registry<testNode> reg{};
    ASSERT_EQ(0UL, reg.size());
}

TEST(unitTestRegistry, CanInsertNode)
{
    registry<testNode> reg{};
    unique_ptr<testNode> node = make_unique<testNode>(42);
    reg.insert_data(std::move(node));

    ASSERT_EQ(1UL, reg.size());
}

TEST(unitTestRegistry, CanLookUpNode)
{
    registry<testNode> reg{};
    unique_ptr<testNode> node = make_unique<testNode>(69);
    reg.insert_data(std::move(node));

    identifier lookup{69};
    const auto search = reg.search(lookup);
    ASSERT_TRUE(search != nullptr);
}
