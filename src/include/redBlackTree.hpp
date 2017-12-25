#pragma once

#include <cassert> //asert()
#include <vector> //std::vector
#include "constants.h" //ID_BYTE_STR
#include "hash.h" //skeinHash()
#include "redBlackStructs.h" //LINK_SIZE, color (enum), rb_direction(enum)
#include "redBlackTreeNode.hpp" //redBlackTree node class
#include "util.h" //compareWordBuff()

#ifdef DBG_RBTREE
#include <iostream> //std::cout, std::endl
using std::cout;
using std::endl;
#endif

using std::vector;

class redBlackTree
{
    public:
    /**************
    * constructor *
    **************/
    explicit redBlackTree();

    /*************
    * destructor *
    *************/
    ~redBlackTree();

    /************************
    * Informational methods *
    ************************/
    size_t size();

    /********************
    * Traversal methods *
    ********************/
    vector<redBlackTreeNode*> listNodes();

    /*******************
    * Deletion methods *
    *******************/
    void deleteByHash(secStr &str);
    void deleteByHex(secStr &id);
    void deleteNode(redBlackTreeNode* node);

    /********************
    * Insertion methods *
    ********************/
    void insertNode(redBlackTreeNode* node);

    /*****************
    * Search methods *
    *****************/
    redBlackTreeNode* searchByHash(secStr &str);
    redBlackTreeNode* searchByHex(secStr &id_hex);

    private:
    /***************
    * private data *
    ***************/
    redBlackTreeNode* root_;
    size_t size_;

    /******************
    * private methods *
    ******************/ 
    #ifdef VERIFY_RBTREE
    /***************************************************************
     * functions to verify red black tree is correctly constructed *
     ***************************************************************/
    void verify_properties();

    /****************************
    * Red Black Tree properties *
    ****************************/
    //1 each node is red or black
    void verify_nodes_red_or_black(redBlackTreeNode* node);

    //2 root node is black
    void verify_root_is_black();

    //3 all leaves are black (NULL nodes count as black)
    void verify_all_leaves_black(redBlackTreeNode* node);

    //4 Every red node must have two black child nodes and black parent
    void verify_red_nodes_surrounded_by_black(redBlackTreeNode* node);

    /*
     * 5
     * All paths from any given node to its leaf nodes contain the same number of black nodes
     */
     void verify_downward_paths_same_depth();
     void v_dp_helper(redBlackTreeNode *node, int black_count, int* path_black_count);

    /* 6
     * nodes left of the parent have a smaller id value then parent
     * nodes right of the parent have a larger id value then parent
     */
     void verify_bst_preserved(redBlackTreeNode* node);
    #endif

    /***************************
    * Node information methods *
    ***************************/

    bool isLeafNode(redBlackTreeNode* node);

    //returns node color + counts NULL as BLACK and anything else as INVALID
    color nodeColor(redBlackTreeNode* node); 

    /********************
    * Insertion methods *
    ********************/
    //Bottom up recursive insert
    redBlackTreeNode* insertHelper(redBlackTreeNode* node, redBlackTreeNode* value);

    /*****************
    * Search methods *
    *****************/
    redBlackTreeNode* searchNodeById(uint64_t* id);
    redBlackTreeNode* searchNode(redBlackTreeNode* value);

    /********************
    * Traversal methods *
    ********************/
    redBlackTreeNode* inOrderTraversal(redBlackTreeNode* node,
                                       vector<redBlackTreeNode*> &storage,
                                       size_t &index
                                      );

    /*******************
    * Deletion methods *
    *******************/
    void deleteNodeInternal(redBlackTreeNode* node);

    /****************************
    * Tree maintainence methods *
    ****************************/
    //tree rotation operations
    redBlackTreeNode*  rbTreeSingleRotate(redBlackTreeNode* node, rb_direction dir);
    redBlackTreeNode*  rbTreeDoubleRotate(redBlackTreeNode* node, rb_direction dir);

    //helper function that handles pointer swapping logic
    void replaceNode(redBlackTreeNode* old_node, redBlackTreeNode* new_node);

    //recursively delete the entire tree below the node passed in
    void teardown(redBlackTreeNode* node);
};
