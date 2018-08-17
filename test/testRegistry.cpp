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
    unique_ptr<testNode> fuck = make_unique<testNode>(42);
    reg.insert_data(std::move(fuck));
}
