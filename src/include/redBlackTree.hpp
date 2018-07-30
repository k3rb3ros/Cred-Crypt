#pragma once

#include <cassert> //asert()
#include <memory> //std::unique_ptr
#include <vector> //std::vector

#include "constants.h" //ID_BYTE_STR
#include "hash.h" //skeinHash()
#include "identifier.hpp" //identifier_t
#include "redBlackTreeNode.hpp" //redBlackTree node class
#include "redBlackUtils.hpp" //LINK_SIZE, color (enum), direction(enum)
#include "secureString.hpp" //secStr

#ifdef DBG_RBTREE
#include <iostream> //std::cout, std::endl
using std::cout;
using std::endl;
#endif

using std::vector;

template <class DATA_TYPE>
class redBlackTree
{
    public:
    /**************
    * constructor *
    **************/
    explicit redBlackTree() = default;

    /*************
    * destructor *
    *************/
    ~redBlackTree();

    /************************
    * Informational methods *
    ************************/
    size_t size() const;

    /********************
    * Traversal methods *
    ********************/
    vector<redBlackTreeNode<DATA_TYPE>*> listNodes() const;

    /*******************
    * Deletion methods *
    *******************/
    void deleteByHash(secStr &str);
    void deleteByHex(secStr &id);
    void deleteNode(redBlackTreeNode<DATA_TYPE>* node);

    /********************
    * Insertion methods *
    ********************/
    void insertNode(std::unique_ptr<redBlackTreeNode<DATA_TYPE>> node);

    /*****************
    * Search methods *
    *****************/
    redBlackTreeNode<DATA_TYPE>* searchByHash(secStr &str) const;
    redBlackTreeNode<DATA_TYPE>* searchByHex(secStr &id_hex) const;

    private:
    /***************
    * private data *
    ***************/
    std::unique_ptr<redBlackTreeNode<DATA_TYPE>*> root_{nullptr};
    size_t size_{0};

    /******************
    * private methods *
    ******************/ 
    #ifdef VERIFY_RBTREE
    /***************************************************************
     * functions to verify red black tree is correctly constructed *
     ***************************************************************/
    void verify_properties() const;

    /****************************
    * Red Black Tree properties *
    ****************************/
    //1 each node is red or black
    void verify_nodes_red_or_black(redBlackTreeNode<DATA_TYPE>* node) const;

    //2 root node is black
    void verify_root_is_black() const;

    //3 all leaves are black (NULL nodes count as black)
    void verify_all_leaves_black(redBlackTreeNode<DATA_TYPE>* node) const;

    //4 Every red node must have two black child nodes and black parent
    void verify_red_nodes_surrounded_by_black(redBlackTreeNode<DATA_TYPE>* node) const;

    /*
     * 5
     * All paths from any given node to its leaf nodes contain the same number of black nodes
     */
    void verify_downward_paths_same_depth() const;
    void v_dp_helper(
        redBlackTreeNode<DATA_TYPE> *node,
        int black_count,
        int* path_black_count) const;

    /* 6
     * nodes left of the parent have a smaller id value then parent
     * nodes right of the parent have a larger id value then parent
     */
    void verify_bst_preserved(redBlackTreeNode<DATA_TYPE>* node) const;
    #endif

    /***************************
    * Node information methods *
    ***************************/

    bool isLeafNode(redBlackTreeNode<DATA_TYPE>* node) const;

    //returns node color + counts NULL as BLACK and anything else as INVALID
    color nodeColor(redBlackTreeNode<DATA_TYPE>* node) const; 

    /********************
    * Insertion methods *
    ********************/
    //Bottom up recursive insert
    redBlackTreeNode<DATA_TYPE>* insertHelper(
        redBlackTreeNode<DATA_TYPE>* node,
        redBlackTreeNode<DATA_TYPE>* value);

    /*****************
    * Search methods *
    *****************/
    redBlackTreeNode<DATA_TYPE>* searchNodeById(const identifier_t* id) const;
    redBlackTreeNode<DATA_TYPE>* searchNode(redBlackTreeNode<DATA_TYPE>* value) const;

    /********************
    * Traversal methods *
    ********************/
    redBlackTreeNode<DATA_TYPE>* inOrderTraversal(
        redBlackTreeNode<DATA_TYPE>* node,
        vector<redBlackTreeNode<DATA_TYPE>*> &storage,
        size_t &index) const;

    /*******************
    * Deletion methods *
    *******************/
    void deleteNodeInternal(redBlackTreeNode<DATA_TYPE>* node);

    /****************************
    * Tree maintainence methods *
    ****************************/
    //tree rotation operations
    redBlackTreeNode<DATA_TYPE>* rbTreeSingleRotate(
        redBlackTreeNode<DATA_TYPE>* node,
        direction dir);

    redBlackTreeNode<DATA_TYPE>* rbTreeDoubleRotate(
        redBlackTreeNode<DATA_TYPE>* node,
        direction dir);

    //helper function that handles pointer swapping logic
    void replaceNode(
        redBlackTreeNode<DATA_TYPE>* old_node,
        redBlackTreeNode<DATA_TYPE>* new_node);

    //recursively delete the entire tree below the node passed in
    void teardown(redBlackTreeNode<DATA_TYPE>* node);
};
