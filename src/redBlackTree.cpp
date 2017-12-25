#include "include/redBlackTree.hpp"

#ifdef VERIFY_RBTREE
void redBlackTree::verify_properties()
{
    verify_nodes_red_or_black(root_);
    verify_root_is_black();
    verify_all_leaves_black(root_);
    verify_red_nodes_surrounded_by_black(root_);
    verify_downward_paths_same_depth();
    verify_bst_preserved(root_);
}

inline void redBlackTree::verify_nodes_red_or_black(redBlackTreeNode* node)
{
    assert(nodeColor(node) == BLACK || nodeColor(node) == RED);
    if (node == nullptr) { return; }

    verify_nodes_red_or_black(node->left());
    verify_nodes_red_or_black(node->right());
}

inline void redBlackTree::verify_root_is_black()
{
    assert(nodeColor(root_) == BLACK);
}

inline void redBlackTree::verify_all_leaves_black(redBlackTreeNode* node)
{ //this property is implied by treating nullptr nodes as black but codeing it out proves it
    if (node == nullptr)
    {
        assert(nodeColor(node) == BLACK);
        return;
    }
    verify_all_leaves_black(node->left());
    verify_all_leaves_black(node->right());
}

inline void redBlackTree::verify_red_nodes_surrounded_by_black(redBlackTreeNode* node)
{
   if (node == nullptr) { return; }

   if (node->left() != nullptr)
   {
       redBlackTreeNode* child = node->left();
       if (child->color() == RED)
       {
           assert(nodeColor(node) == BLACK); //parent
           assert(nodeColor(child) == RED);
           assert(nodeColor(child->left()) == BLACK);
           assert(nodeColor(child->right()) == BLACK);
       }
   }

   if (node->right() != nullptr)
   {
       redBlackTreeNode* child = node->right();
       if (child->color() == RED)
       {
           assert(nodeColor(node) == BLACK); //parent
           assert(nodeColor(child) == RED);
           assert(nodeColor(child->left()) == BLACK);
           assert(nodeColor(child->right()) == BLACK);
       }
   }

   verify_red_nodes_surrounded_by_black(node->left()); 
   verify_red_nodes_surrounded_by_black(node->right()); 
}

void redBlackTree::verify_downward_paths_same_depth()
{
    int path_black_count = -1;
    v_dp_helper(root_, 0, &path_black_count);
}

inline void redBlackTree::v_dp_helper(redBlackTreeNode *node, int black_count, int* path_black_count)
{
    if (nodeColor(node) == BLACK) { black_count++; }
    if (node == nullptr)
    {
        if (*path_black_count == -1) { *path_black_count = black_count; }
        else { assert(black_count == *path_black_count); }
        return;
    }
    v_dp_helper(node->left(), black_count, path_black_count);
    v_dp_helper(node->right(), black_count, path_black_count);
}

void redBlackTree::verify_bst_preserved(redBlackTreeNode* node)
{
    if (node == nullptr) { return; }
    if (node->left() != nullptr)
    { 
        assert(compareWordBuff(node->left()->getID(), node->getID(), ID_WORD_SIZE) < 0);
    }
    if (node->right() != nullptr)
    { 
        assert(compareWordBuff(node->right()->getID(), node->getID(), ID_WORD_SIZE) > 0);
    }

    verify_bst_preserved(node->left());
    verify_bst_preserved(node->right());
}
#endif

bool redBlackTree::isLeafNode(redBlackTreeNode* node) { return node->left() == nullptr && node->right() == nullptr; }

inline color redBlackTree::nodeColor(redBlackTreeNode* node)
{
    if (node == nullptr) { return BLACK; } //null nodes count as BLACK
    //only RED and BLACK are valid colors anything else is invalid
    return (node->color() == RED || node->color() == BLACK) ? node->color() : INVALID;
}

redBlackTreeNode* redBlackTree::insertHelper(redBlackTreeNode* node, redBlackTreeNode* new_node)
{
    if (node == nullptr) //rb_tree_node doesn't yet exist so create it
    {
        node = new_node;
        this->size_++;
    }
    //if this isn't the node we are inserting
    else if (compareWordBuff(new_node->getID(), node->getID(), ID_WORD_SIZE) != 0)
    { 
        rb_direction dir = (compareWordBuff(new_node->getID(), node->getID(), ID_WORD_SIZE) < 0)
                            ? LEFT : RIGHT;

        node->link()[dir] = insertHelper(node->link()[dir], new_node);

        /**************************
         * Begin Rebalancing code *
         *************************/
        if (nodeColor(node->link()[dir]) == RED)
        {
            if ((nodeColor(node->link()[oppDir(dir)])) == RED)
            {
                //Case 1
                node->color() = RED;
                node->left()->color() = BLACK;
                node->right()->color() = BLACK;
            }
            else
            {
                //Case 2
                if (nodeColor(node->link()[dir]->link()[dir]) == RED)
                {
                    node = rbTreeSingleRotate(node, oppDir(dir));
                }
                else if (nodeColor(node->link()[dir]->link()[oppDir(dir)]) == RED) //Case 3
                {
                    node = rbTreeDoubleRotate(node, oppDir(dir));
                }
            }
        }
        /*************************
        *  End Rebalancing code  *
        *************************/
    }
    else //update an existing node in place (no tree rebalance necessary)
    {
        assert(compareWordBuff(new_node->getID(), node->getID(), ID_WORD_SIZE) == 0);

        //swap the values between the new and the old node
        nodeValueBase* prev_val = node->value();
        *(node->value()) = *(new_node->value());
        *(new_node->value()) = *(prev_val);
        //node->value() = value->value();
        //value->value() = prev_val;

        delete new_node; //delete the new node with the old value in it
    }

    return node;
}

redBlackTreeNode* redBlackTree::searchNodeById(uint64_t* id)
{
    redBlackTreeNode* search = nullptr;    

    if (root_ != nullptr && id != nullptr)
    {
        search = root_;

        while (search != nullptr)
        {
            if (compareWordBuff(search->getID(), id, ID_WORD_SIZE) == 0) { return search; } //found it
            else if (compareWordBuff(search->getID(), id, ID_WORD_SIZE) > 0) //traverse left
            {
                search = search->left();
            }
            else //traverse right
            {
                assert(compareWordBuff(search->getID(), id, ID_WORD_SIZE) < 0);
                search = search->right();
            }
        }
    }

    return search;
}

redBlackTreeNode* redBlackTree::searchNode(redBlackTreeNode* node)
{
    redBlackTreeNode* search = nullptr;

    if (root_ != nullptr && node != nullptr)
    {
        uint64_t* tgt_id = node->getID();
        search = root_;

        while (search != nullptr)
        {
            //found it
            if (compareWordBuff(search->getID(), node->getID(), ID_WORD_SIZE) == 0) { break; }
            else if (compareWordBuff(search->getID(), node->getID(), ID_WORD_SIZE) > 0) //traverse left
            {
                search = search->left();
            }
            else //traverse right
            {
                assert(compareWordBuff(search->getID(), tgt_id, ID_WORD_SIZE) < 0);
                search = search->right();
            }
        }
    }
 
    return search;
}

void redBlackTree::deleteNodeInternal(redBlackTreeNode* node)
{
    if (this->root_ != nullptr && node != nullptr)
    {
        redBlackTreeNode head; /* False tree root */
        redBlackTreeNode* q = nullptr; /* Helpers */
        redBlackTreeNode* p = nullptr; /* Helpers */
        redBlackTreeNode* g = nullptr; /* Helpers */
        redBlackTreeNode* f = nullptr; /* Found item */
        rb_direction dir = RIGHT;

        /* Set up helpers */
        q = &head;
        q->right() = this->root_;

        /* Search and push a red down */
        while (q->link()[dir] != nullptr)
        {
            rb_direction last = dir;

            /* Update helpers */
            g = p;
            p = q;
            q = q->link()[dir];
            dir = (compareWordBuff(q->getID(), node->getID(), ID_WORD_SIZE) < 0) ? RIGHT : LEFT;

            /* Save found node */
            if (compareWordBuff(q->getID(), node->getID(), ID_WORD_SIZE) == 0)
            {
                f = q;
            }

            /* Push the red node down */
            if (!isLeafNode(q) && nodeColor(q) == BLACK && nodeColor(q->link()[dir]) == BLACK)
            {
                if (nodeColor(q->link()[oppDir(dir)]) == RED)
                {
                    /* single rotation */
                    p = p->link()[last] = rbTreeSingleRotate(q, dir);
                }
                else if (nodeColor(q->link()[oppDir(dir)]) == BLACK)
                {
                    redBlackTreeNode* s = p->link()[oppDir(last)];

                    if (s != nullptr)
                    {
                        if (nodeColor(s->link()[oppDir(last)]) == BLACK && nodeColor(s->link()[last]) == BLACK)
                        {
                            /* Color flip */
                            p->color() = BLACK;
                            s->color() = RED;
                            q->color() = RED;
                        }
                        else
                        {
                            rb_direction dir2 = (g->right() == p) ? RIGHT : LEFT;

                            if (nodeColor(s->link()[last]) == RED)
                            {
                                /* double rotation */
                                g->link()[dir2] = rbTreeDoubleRotate(p, dir2);
                            }
                            else if (nodeColor(s->link()[oppDir(last)]) == RED)
                            {
                                /* single rotation */
                                g->link()[dir2] = rbTreeSingleRotate(p, last);
                            }

                            /* Ensure correct coloring */
                            q->color() = RED;
                            g->link()[dir2]->color() = RED;
                            g->link()[dir2]->left()->color() = BLACK;
                            g->link()[dir2]->right()->color() = BLACK;
                        }
                    }
                }
            }
        } /*End while */

        /* Replace and remove if found i.e. delete the node*/
        if (f != nullptr)
        {
            nodeValueBase* d = f->value();

            *(f->value()) = *(q->value());
            *(q->value()) = *d;

            rb_direction p_link = p->right() == q ? RIGHT : LEFT;
            rb_direction q_link = q->left() == nullptr ? RIGHT : LEFT;
            p->link()[p_link] = q->link()[q_link];

            size_--; //decriment node count
            delete q; //delete the node
        }

        /* Update root and make it black */
        this->root_ = (head.right());

        if (this->root_ != nullptr) //ensure root is black
        {
            this->root_->color() = BLACK;
        }
    }

    #ifdef VERIFY_RBTREE
    verify_properties(); //verify that the tree isn't broken 
    #endif
}

redBlackTreeNode* redBlackTree::rbTreeSingleRotate(redBlackTreeNode* node, rb_direction dir)
{
    redBlackTreeNode* save = node->link()[oppDir(dir)];

    node->link()[oppDir(dir)] = save->link()[dir];
    save->link()[dir] = node;

    node->color() = RED;
    save->color() = BLACK;

    return save;
}

redBlackTreeNode* redBlackTree::rbTreeDoubleRotate(redBlackTreeNode* node, rb_direction dir)
{
    node->link()[oppDir(dir)] = rbTreeSingleRotate(node->link()[oppDir(dir)], oppDir(dir));

    return rbTreeSingleRotate(node, dir);
}

void redBlackTree::teardown(redBlackTreeNode* node)
{
    #ifdef DBG_RBTREE
    cout << "teardown called on " << node << endl;
    #endif
    if (node == nullptr) { return; }
    if (node->left() != nullptr)
    {
        teardown(node->left());
        node->left() = nullptr;
    }
    if (node->right() != nullptr)
    {
        teardown(node->right());
        node->right() = nullptr;
    }

    delete node;
}

redBlackTree::redBlackTree() : root_(nullptr), size_(0) 
{ /*nop*/ }

size_t redBlackTree::size()
{
    return size_;
}

redBlackTreeNode* redBlackTree::searchByHex(secStr &id_hex)
{
    redBlackTreeNode* search = nullptr;

    uint64_t id[ID_WORD_SIZE] = { 0 };
    hexDecode(id_hex.byteStr(), (uint8_t*)id, id_hex.size());

    search = searchNodeById(id);

    return search;
}

redBlackTreeNode* redBlackTree::searchByHash(secStr &str)
{
    redBlackTreeNode* search = nullptr;
    uint64_t id[ID_WORD_SIZE] = { 0 };

    if (skeinHash(str.byteStr(), str.size(), (uint8_t*)id, (ID_BYTE_SIZE)))
    {
        search = searchNodeById(id);
    }

    return search != nullptr ? search : nullptr;
}

vector<redBlackTreeNode*> redBlackTree::listNodes()
{
    vector<redBlackTreeNode*> nodes(size_);
    size_t index = 0;

    inOrderTraversal(root_, nodes, index);

    return nodes;
}

redBlackTreeNode* redBlackTree::inOrderTraversal(redBlackTreeNode* node,
                                                 vector<redBlackTreeNode*> &storage,
                                                 size_t &index)
{
    if (node != nullptr)
    {
        if (node->left() != nullptr)
        { inOrderTraversal(node->left(), storage, index); }

        if (node != nullptr) { storage[index++] = node; }

        if (node->right() != nullptr)
        { inOrderTraversal(node->right(), storage, index); }
    }

    return nullptr;
}

void redBlackTree::deleteByHex(secStr &id_hex)
{
    deleteNodeInternal(searchByHex(id_hex));
}

void redBlackTree::deleteByHash(secStr &str)
{
    deleteNodeInternal(searchByHash(str));
}

void redBlackTree::deleteNode(redBlackTreeNode* node)
{
    deleteNodeInternal(node);
}

void redBlackTree::insertNode(redBlackTreeNode* node)
{
    if (node != nullptr)
    {
        /* Insert helper starts at root and recursively adds the node and adjusts the tree as
         * necessary, returning the new root
         */
        this->root_ = insertHelper(this->root_, node);
        this->root_->color() = BLACK; //root should always be black
    }
    
    #ifdef VERIFY_RBTREE
    verify_properties(); //verify that the tree isn't broken 
    #endif
} 

redBlackTree::~redBlackTree()
{
    #ifdef DBG_RBTREE
    cout << "RBTree destructor" << endl;
    #endif
    teardown(root_);
}
 
