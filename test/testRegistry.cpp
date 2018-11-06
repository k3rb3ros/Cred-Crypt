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
    reg.insert(std::move(node));

    ASSERT_EQ(1UL, reg.size());
}

TEST(unitTestRegistry, CanLookUpNode)
{
    registry<testNode> reg{};
    unique_ptr<testNode> node = make_unique<testNode>(69);
    reg.insert(std::move(node));

    ASSERT_TRUE(reg.search(identifier{69}) != nullptr);
}

TEST(unitTestRegistry, SearchReturnsNullptrWhenNodeDoesntExist)
{
    registry<testNode> reg{};
    unique_ptr<testNode> node = make_unique<testNode>(1);
    unique_ptr<testNode> node1 = make_unique<testNode>(1000);

    reg.insert(std::move(node));
    reg.insert(std::move(node1));

    ASSERT_TRUE(reg.search(identifier{50}) == nullptr);
}

TEST(unitTestRegistry, SearchReturnsNodeWhenExists)
{
    registry<testNode> reg{};
    unique_ptr<testNode> node = make_unique<testNode>(14);

    reg.insert(std::move(node));

    ASSERT_TRUE(reg.search(identifier{14}) != nullptr);
}

TEST(unitTestRegistry, ExistsReturnsFalseOnEmptyRegistry)
{
    registry<testNode> reg{};

    ASSERT_FALSE(reg.exists(identifier{432}));
}

TEST(unitTestRegistry, ExistsReturnsTrueForInsertedNode)
{
    registry<testNode> reg{};
    unique_ptr<testNode> node = make_unique<testNode>(3);
    reg.insert(std::move(node));

    ASSERT_TRUE(reg.exists(identifier{3}));
}

TEST(unitTestRegistry, DeleteReturnFalseWhenPassedInvalidId)
{
    registry<testNode> reg{};

    ASSERT_FALSE(reg.erase(identifier{13}));
}

TEST(unitTestRegistry, DeleteRemovesNodeFromRegistry)
{
    registry<testNode> reg{};
    unique_ptr<testNode> node = make_unique<testNode>(420);
    reg.insert(std::move(node));

    ASSERT_EQ(1UL, reg.size());
    ASSERT_TRUE(reg.erase(identifier{420}));
    ASSERT_EQ(0UL, reg.size());
}

TEST(unitTestRegistry, TraverseReturnEmptyVectorWhenRegEmpty)
{
    registry<testNode> reg{};

    const auto nodes = reg.traverse();
    ASSERT_EQ(0UL, nodes.size());
}

TEST(unitTestRegistry, TraverseReturnsSortedVectorOfNodesWhenTheyExist)
{
    registry<testNode> reg{};

    // add 100 nodes counting backwards
    for (uint64_t i=100; i>0; --i)
    {
        unique_ptr<testNode> node = make_unique<testNode>(i);
        reg.insert(std::move(node));
    }

    // traverse the registry
    const auto trav = reg.traverse();

    // verify there are 100 nodes
    ASSERT_EQ(100UL, reg.size());

    // verify the nodes are in sorted order and valued from 1-100
    for (uint64_t i=0; i<100; ++i)
    {
        const auto compare = trav[i];
        ASSERT_EQ(i+1, compare->get_id().data()[0]);
    }
}

TEST(unitTestRegistry, RegistryCanHandleOverOneHundredThousandNodes)
{
    registry<testNode> reg{};

    // add 100000 nodes counting backwards
    for (uint64_t i=100000; i>0; --i)
    {
        unique_ptr<testNode> node = make_unique<testNode>(i);
        reg.insert(std::move(node));
    }

    // verify there are 100000 nodes
    ASSERT_EQ(100000UL, reg.size());

    // delete 3 nodes
    reg.erase(identifier{1});
    reg.erase(identifier{42});
    reg.erase(identifier{69});
    ASSERT_EQ(100000UL-3UL, reg.size());

    // test a sampling of nodes to ensure they have the correct value
    auto search = reg.search(identifier{3});
    ASSERT_EQ(3UL, search->get_value());

    search = reg.search(identifier{69});
    ASSERT_EQ(nullptr, search);

    search = reg.search(identifier{100000});
    ASSERT_EQ(100000UL, search->get_value());
}
