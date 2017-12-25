#include "include/testRedBlackTree.hpp"

/* A freshly created rbtree should have a size of zero */
TEST(unitTestRedBlackTree, RBTreeInitSizeIsZero)
{
    redBlackTree tree;
    ASSERT_EQ(tree.size(), 0ULL);
}

/* A freshly created rbtree should have no nodes in it */
TEST(unitTestRedBlackTree, RBTreeInitTreeIsEmpty)
{
    redBlackTree tree;
    vector<redBlackTreeNode*> no_nodes = tree.listNodes();
    ASSERT_EQ(no_nodes.size(), 0ULL);
}

/* With no nodes any search by Hash should return NULL */
TEST(unitTestRedBlackTree, RBTreeEmptySearchByHashIsNull)
{
    redBlackTree tree;
    secStr s1("abc");
    secStr s2("cba");
    secStr s3("_");
    secStr s4("1");
    redBlackTreeNode* search = tree.searchByHash(s1);
    redBlackTreeNode* search2 = tree.searchByHash(s2);
    redBlackTreeNode* search3 = tree.searchByHash(s3);
    redBlackTreeNode* search4 = tree.searchByHash(s4);
    ASSERT_EQ(search, nullptr);
    ASSERT_EQ(search2, nullptr);
    ASSERT_EQ(search3, nullptr);
    ASSERT_EQ(search4, nullptr);
}

/* With no nodes any search by Hex should return NULL */
TEST(unitTestRedBlackTree, RBTreeEmptySearchByHexIsNull)
{
    redBlackTree tree;
    secStr id_hex_null("");
    secStr id_hex("1234");
    redBlackTreeNode* search = tree.searchByHex(id_hex_null);
    ASSERT_EQ(search, nullptr);
    search = tree.searchByHex(id_hex);
    ASSERT_EQ(search, nullptr);
}

/* Put a node in the tree and ensure it can be retrieved and deleted */
TEST(unitTestRedBlackTree, RBTreeCanInsertNode)
{
    redBlackTree tree;
    mockNodeValue* N1 = new mockNodeValue(1);
    redBlackTreeNode* node = new redBlackTreeNode(N1);

    ASSERT_EQ(tree.size(), 0ULL);
    tree.insertNode(node);
    secStr query("1");
    ASSERT_EQ(tree.size(), 1ULL);
    redBlackTreeNode* search = tree.searchByHash(query);
    ASSERT_NE(search, nullptr);
}

/* Can insert two nodes delete one and then insert another */
//TODO write test

/* Search by HashOfStr retrieves correct node */
TEST(unitTestRedBlackTree, RBTreeSearchByKeyFindsCorrectNode)
{
    redBlackTree tree;

    /* Add 1000 test nodes to the tree */
    for (uint64_t s=1; s<=1000; ++s)
    {
        tree.insertNode(new redBlackTreeNode(new mockNodeValue(s)));
    }

    /* Ensure there are 1000 nodes in the tree */
    ASSERT_EQ(tree.size(), 1000ULL);
    
    secStr query_42("42");
    redBlackTreeNode* search = tree.searchByHash(query_42);
    ASSERT_NE(search, nullptr);
    mockNodeValue* node = (mockNodeValue*)search->value();
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(node->value(), 42ULL);

    secStr query_69("69");
    search = tree.searchByHash(query_69);
    ASSERT_NE(search, nullptr);
    node = (mockNodeValue*)search->value();
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(node->value(), 69ULL);
}

/* search by IdHex retrievies correct node */
TEST(unitTestRedBlackTree, RBTreeSearchByIdHexFindsCorrectNode)
{
    redBlackTree tree;

    /* insert 3 nodes into the tree */
    tree.insertNode(new redBlackTreeNode(new mockNodeValue(7)));
    tree.insertNode(new redBlackTreeNode(new mockNodeValue(17)));
    tree.insertNode(new redBlackTreeNode(new mockNodeValue(19)));

    secStr hex_query("a958f4c5461bb31ded7b222af58bb189c1db406e1506604b3c9bf395209510f820effa4e1d554329ec9ebdf8b59d829bd9ebabeda482c8fb709b27d077fa68d9");
    redBlackTreeNode* search = tree.searchByHex(hex_query);
    ASSERT_NE(search, nullptr);
    mockNodeValue* val = (mockNodeValue*)search->value();
    ASSERT_EQ(val->value(), 17ULL);
}

//TODO listNodes lists all nodes in the tree

/* Test that tree can handle adding multiple nodes and a tree of multiple nodes only deletes the correct node
 */
TEST(unitTestRedBlackTree, RBTreeCanDeleteNodeByHash)
{
    redBlackTree tree;

    /* Add 1000 test nodes to the tree */
    for (uint64_t s=1; s<=1000; ++s)
    {
        tree.insertNode(new redBlackTreeNode(new mockNodeValue(s)));
    }

    /* Ensure there are 1000 nodes in the tree */
    ASSERT_EQ(tree.size(), 1000ULL);

    /* delete the 66 node by hash then test that we can't search for it anymore */
    secStr query("66");
    redBlackTreeNode* deleteMe = tree.searchByHash(query);
    ASSERT_NE(deleteMe, nullptr);
    tree.deleteByHash(query);
    ASSERT_EQ(tree.size(), 999ULL);
    deleteMe = tree.searchByHash(query);
    ASSERT_EQ(deleteMe, nullptr);
    
    /* Check that the nearby (valued) nodes where not inadvertently deleted
     * now that nodes are hashed it hard to deterministically know where a given node will be
     * so we care move that the node has gone down by one then the adjacently numbered nodes
     * are still reachable (although verifying this is still a +)*/
    secStr q_65("65");
    redBlackTreeNode* search = tree.searchByHash(q_65);
    ASSERT_NE(search, nullptr);
    mockNodeValue* val = (mockNodeValue*)search->value();
    ASSERT_NE(val, nullptr);
    ASSERT_EQ(val->value(), 65ULL);

    secStr q_67("67");
    search = tree.searchByHash(q_67);
    ASSERT_NE(search, nullptr);
    val = (mockNodeValue*)search->value();
    ASSERT_NE(val, nullptr);
    ASSERT_EQ(val->value(), 67ULL);
}

//TODO can delete by Hex

//TODO can delete by Node

/* Adding Lots of unique nodes doesn't break anything */
TEST(unitTestRedBlackTree, RBTreeWorksWLotsOfNodes)
{
    redBlackTree tree;

    for (uint64_t s=1; s<=1000000; ++s)
    {
        tree.insertNode(new redBlackTreeNode(new mockNodeValue(s)));
    }

    /* Ensure there are 1000000 nodes in the tree */
    ASSERT_EQ(tree.size(), 1000000ULL);

    /* Do some sanity checking on the contents and range of the nodes ensuring we can find
     * nodes in the range that should be in the tree
     */
    secStr q_42("42");
    mockNodeValue* node = (mockNodeValue*)tree.searchByHash(q_42)->value();
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(node->value(), 42ULL);

    secStr q_3fiddy("350");
    node = (mockNodeValue*)tree.searchByHash(q_3fiddy)->value();
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(node->value(), 350ULL);

    secStr q_kilo("1000");
    node = (mockNodeValue*)tree.searchByHash(q_kilo)->value();
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(node->value(), 1000ULL);

    secStr q_one_hundred_k("100000");
    node = (mockNodeValue*)tree.searchByHash(q_one_hundred_k)->value();
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(node->value(), 100000ULL);
}

TEST(unitTestRedBlackTree, RBTreeAddingDuplicateNodeOverridesExisting)
{
    redBlackTree tree;

    /* Add 100 unique nodes */
    for (uint64_t s=1; s<=100; ++s)
    {
        tree.insertNode(new redBlackTreeNode(new mockNodeValue(s)));
    }

    ASSERT_EQ(tree.size(), 100ULL);
 
    /* Create additional nodes that will collide existing nodes in the trees */   
    mockNodeValue* n1 = new mockNodeValue(42);
    mockNodeValue* n2 = new mockNodeValue(69);
    mockNodeValue* n3 = new mockNodeValue(1);
    mockNodeValue* n4 = new mockNodeValue(100);
    redBlackTreeNode* r1 = new redBlackTreeNode(n1);
    redBlackTreeNode* r2 = new redBlackTreeNode(n2);
    redBlackTreeNode* r3 = new redBlackTreeNode(n3);
    redBlackTreeNode* r4 = new redBlackTreeNode(n4);
    
    /* Nodes with the same Key value should replace existing nodes with the same key
     * so node count should remain unchanged */
    tree.insertNode(r1);
    tree.insertNode(r2);
    tree.insertNode(r3);
    tree.insertNode(r4);
    ASSERT_EQ(tree.size(), 100ULL);
}

/* Adding tons of potentially conflicting nodes doesn't break anything */
TEST(unitTestRedBlackTree, RBTreeAddingDupNodesToLargeTree)
{
    redBlackTree tree;

    /* Add 10000 unique nodes into tree */
    for (uint64_t s=1; s<=10000; ++s)
    {
        tree.insertNode(new redBlackTreeNode(new mockNodeValue(s)));
    }

    /* Ensure there are 10000 nodes in the tree */
    ASSERT_EQ(tree.size(), 10000ULL);

    /* Insert threie duplicate nodes they should be inserted on top of the existing nodes
     * so the tree size should remain unchanged
     */
    tree.insertNode(new redBlackTreeNode(new mockNodeValue(69)));
    tree.insertNode(new redBlackTreeNode(new mockNodeValue(4442)));
    tree.insertNode(new redBlackTreeNode(new mockNodeValue(6679)));

    ASSERT_EQ(tree.size(), 10000ULL);

    secStr q1("69");
    secStr q2("4442");
    secStr q3("6679");
    redBlackTreeNode* search = tree.searchByHash(q1);
    mockNodeValue* s_val = (mockNodeValue*)search->value();
    ASSERT_NE(search, nullptr);
    ASSERT_EQ(s_val->value(), 69ULL);
    search = tree.searchByHash(q2);
    s_val = (mockNodeValue*)search->value();
    ASSERT_NE(search, nullptr);
    ASSERT_EQ(s_val->value(), 4442ULL);
    search = tree.searchByHash(q3);
    s_val = (mockNodeValue*)search->value();
    ASSERT_NE(search, nullptr);
    ASSERT_EQ(s_val->value(), 6679ULL);
}

/* TODO We can retrieve and iterate all values in a tree with multiple nodes */
