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
        assert(node->left()->getID() < node->getID());
    }
    if (node->right() != nullptr)
    { 
        assert(node->right()->getID() > node->getID());
    }

    verify_bst_preserved(node->left());
    verify_bst_preserved(node->right());
}
#endif

template <class DATA_TYPE>
bool redBlackTree<DATA_TYPE>::isLeafNode(redBlackTreeNode<DATA_TYPE>* node) const
{ return node->left() == nullptr && node->right() == nullptr; }

template <class DATA_TYPE>
inline color redBlackTree<DATA_TYPE>::nodeColor(redBlackTreeNode<DATA_TYPE>* node) const
{
    if (node == nullptr) { return color::BLACK; } //null nodes count as BLACK
    //only RED and BLACK are valid colors anything else is invalid
    return (node->color() == color::RED || node->color() == color::BLACK) ?
        node->color() : color::INVALID;
}

template <class DATA_TYPE>
redBlackTreeNode<DATA_TYPE>* redBlackTree<DATA_TYPE>::insertHelper(
    redBlackTreeNode<DATA_TYPE>* node,
    redBlackTreeNode<DATA_TYPE>* new_node)
{
    if (node == nullptr) //rb_tree_node doesn't yet exist so create it
    {
        node = new_node;
        this->size_++;
    }
    //if this isn't the node we are inserting
    else if (new_node->getID() != node->getID())
    { 
        direction dir = (new_node->getID() < node->getID())
            ? direction::LEFT : direction::RIGHT;

        node->link()[dir] = insertHelper(node->link()[dir], new_node);

        /**************************
         * Begin Rebalancing code *
         *************************/
        if (nodeColor(node->link()[dir]) == color::RED)
        {
            if ((nodeColor(node->link()[oppDir(dir)])) == color::RED)
            {
                //Case 1
                node->color() = color::RED;
                node->left()->color() = color::BLACK;
                node->right()->color() = color::BLACK;
            }
            else
            {
                //Case 2
                if (nodeColor(node->link()[dir]->link()[dir]) == color::RED)
                {
                    node = rbTreeSingleRotate(node, oppDir(dir));
                }
                // Case 3
                else if (nodeColor(node->link()[dir]->link()[oppDir(dir)]) == color::RED)
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
        assert(node == new_node);

        //TODO finish me
        //swap the values between the new and the old node
        std::unique_ptr<redBlackTreeNode<DATA_TYPE>> prev_val = node->getData();
        node->setData(new_node->getData());
        //*(node->value()) = *(new_node->value());
        //*(new_node->value()) = *(prev_val);
        //node->value() = value->value();
        //value->value() = prev_val;

        delete new_node; //delete the new node with the old value in it
    }

    return node;
}

template <class DATA_TYPE>
redBlackTreeNode<DATA_TYPE>* redBlackTree<DATA_TYPE>::searchNodeById(const identifier_t* id) const
{
    redBlackTreeNode<DATA_TYPE>* search = nullptr;    

    if (root_ != nullptr && id != nullptr)
    {
        search = root_;

        while (search != nullptr)
        {
            // found it
            if (compareWordBuff(search->getID(), id, ID_WORD_SIZE) == 0) { return search; }
            // traverse left
            else if (compareWordBuff(search->getID(), id, ID_WORD_SIZE) > 0)
            {
                search = search->left();
            }
            // traverse right
            else
            {
                assert(compareWordBuff(search->getID(), id, ID_WORD_SIZE) < 0);
                search = search->right();
            }
        }
    }

    return search;
}

template <class DATA_TYPE>
redBlackTreeNode<DATA_TYPE>* redBlackTree<DATA_TYPE>::searchNode(
    redBlackTreeNode<DATA_TYPE>* node) const
{
    redBlackTreeNode<DATA_TYPE>* search = nullptr;

    if (root_ != nullptr && node != nullptr)
    {
        uint64_t* tgt_id = node->getID();
        search = root_;

        while (search != nullptr)
        {
            //found it
            if (compareWordBuff(search->getID(), node->getID(), ID_WORD_SIZE) == 0) { break; }
            // traverse left
            else if (compareWordBuff(search->getID(), node->getID(), ID_WORD_SIZE) > 0)
            {
                search = search->left();
            }
            // traverse right
            else
            {
                assert(compareWordBuff(search->getID(), tgt_id, ID_WORD_SIZE) < 0);
                search = search->right();
            }
        }
    }
 
    return search;
}

template <class DATA_TYPE>
void redBlackTree<DATA_TYPE>::deleteNodeInternal(redBlackTreeNode<DATA_TYPE>* node)
{
    if (this->root_ != nullptr && node != nullptr)
    {
        redBlackTreeNode<DATA_TYPE> head; /* False tree root */
        redBlackTreeNode<DATA_TYPE>* q = nullptr; /* Helpers */
        redBlackTreeNode<DATA_TYPE>* p = nullptr; /* Helpers */
        redBlackTreeNode<DATA_TYPE>* g = nullptr; /* Helpers */
        redBlackTreeNode<DATA_TYPE>* f = nullptr; /* Found item */
        direction dir = direction::RIGHT;

        /* Set up helpers */
        q = &head;
        q->right() = this->root_;

        /* Search and push a red down */
        while (q->link()[dir] != nullptr)
        {
            direction last = dir;

            /* Update helpers */
            g = p;
            p = q;
            q = q->link()[dir];
            dir = (q->getID() < node->getID()) ? direction::RIGHT : direction::LEFT;

            /* Save found node */
            if (q->getID() == node->getID())
            {
                f = q;
            }

            /* Push the red node down */
            if (!isLeafNode(q) &&
                nodeColor(q) == color::BLACK &&
                nodeColor(q->link()[dir]) == color::BLACK)
            {
                if (nodeColor(q->link()[oppDir(dir)]) == color::RED)
                {
                    /* single rotation */
                    p = p->link()[last] = rbTreeSingleRotate(q, dir);
                }
                else if (nodeColor(q->link()[oppDir(dir)]) == color::BLACK)
                {
                    redBlackTreeNode<DATA_TYPE>* s = p->link()[oppDir(last)];

                    if (s != nullptr)
                    {
                        if (nodeColor(s->link()[oppDir(last)]) == color::BLACK &&
                            nodeColor(s->link()[last]) == color::BLACK)
                        {
                            /* Color flip */
                            p->color() = color::BLACK;
                            s->color() = color::RED;
                            q->color() = color::RED;
                        }
                        else
                        {
                            direction dir2 = (g->right() == p) ? direction::RIGHT : direction::LEFT;

                            if (nodeColor(s->link()[last]) == color::RED)
                            {
                                /* double rotation */
                                g->link()[dir2] = rbTreeDoubleRotate(p, dir2);
                            }
                            else if (nodeColor(s->link()[oppDir(last)]) == color::RED)
                            {
                                /* single rotation */
                                g->link()[dir2] = rbTreeSingleRotate(p, last);
                            }

                            /* Ensure correct coloring */
                            q->color() = color::RED;
                            g->link()[dir2]->color() = color::RED;
                            g->link()[dir2]->left()->color() = color::BLACK;
                            g->link()[dir2]->right()->color() = color::BLACK;
                        }
                    }
                }
            }
        } /*End while */

        /* Replace and remove if found i.e. delete the node*/
        if (f != nullptr)
        {
            std::swap(f->getData(), q->getData());

            direction p_link = p->right() == q ? direction::RIGHT : direction::LEFT;
            direction q_link = q->left() == nullptr ? direction::RIGHT : direction::LEFT;
            p->link()[p_link] = q->link()[q_link];

            size_--; //decriment node count
        }

        /* Update root and make it black */
        this->root_ = (head.right());

        if (this->root_ != nullptr) //ensure root is black
        {
            this->root_->color() = color::BLACK;
        }
    }

    #ifdef VERIFY_RBTREE
    verify_properties(); //verify that the tree isn't broken 
    #endif
}

template <class DATA_TYPE>
redBlackTreeNode<DATA_TYPE>* redBlackTree<DATA_TYPE>::rbTreeSingleRotate(
    redBlackTreeNode<DATA_TYPE>* node,
    direction dir)
{
    redBlackTreeNode<DATA_TYPE>* save = node->link()[oppDir(dir)];

    node->link()[oppDir(dir)] = save->link()[dir];
    save->link()[dir] = node;

    node->color() = color::RED;
    save->color() = color::BLACK;

    return save;
}

template <class DATA_TYPE>
redBlackTreeNode<DATA_TYPE>* redBlackTree<DATA_TYPE>::rbTreeDoubleRotate(
    redBlackTreeNode<DATA_TYPE>* node,
    direction dir)
{
    node->link()[oppDir(dir)] = rbTreeSingleRotate(node->link()[oppDir(dir)], oppDir(dir));

    return rbTreeSingleRotate(node, dir);
}

template <class DATA_TYPE>
void redBlackTree<DATA_TYPE>::teardown(redBlackTreeNode<DATA_TYPE>* node)
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
}

template <class DATA_TYPE>
size_t redBlackTree<DATA_TYPE>::size() const
{
    return size_;
}

template <class DATA_TYPE>
redBlackTreeNode<DATA_TYPE>* redBlackTree<DATA_TYPE>::searchByHex(secStr &id_hex) const
{
    redBlackTreeNode<DATA_TYPE>* search = nullptr;

    uint64_t id[ID_WORD_SIZE] = { 0 };
    hexDecode(id_hex.byteStr(), reinterpret_cast<uint8_t*>(id), id_hex.size());

    search = searchNodeById(id);

    return search;
}

template <class DATA_TYPE>
redBlackTreeNode<DATA_TYPE>* redBlackTree<DATA_TYPE>::searchByHash(secStr &str) const
{
    redBlackTreeNode<DATA_TYPE>* search = nullptr;
    uint64_t id[ID_WORD_SIZE] = { 0 };

    if (skeinHash(str.byteStr(), str.size(), reinterpret_cast<uint8_t*>(id), (ID_BYTE_SIZE)))
    {
        search = searchNodeById(id);
    }

    return search != nullptr ? search : nullptr;
}

template <class DATA_TYPE>
vector<redBlackTreeNode<DATA_TYPE>*> redBlackTree<DATA_TYPE>::listNodes() const
{
    vector<redBlackTreeNode<DATA_TYPE>*> nodes(size_);
    size_t index = 0;

    inOrderTraversal(root_, nodes, index);

    return nodes;
}

template <class DATA_TYPE>
redBlackTreeNode<DATA_TYPE>* redBlackTree<DATA_TYPE>::inOrderTraversal(
    redBlackTreeNode<DATA_TYPE>* node,
    vector<redBlackTreeNode<DATA_TYPE>*> &storage,
    size_t &index) const
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

template <class DATA_TYPE>
void redBlackTree<DATA_TYPE>::deleteByHex(secStr &id_hex)
{
    deleteNodeInternal(searchByHex(id_hex));
}

template <class DATA_TYPE>
void redBlackTree<DATA_TYPE>::deleteByHash(secStr &str)
{
    deleteNodeInternal(searchByHash(str));
}

template <class DATA_TYPE>
void redBlackTree<DATA_TYPE>::deleteNode(redBlackTreeNode<DATA_TYPE>* node)
{
    deleteNodeInternal(node);
}

template <class DATA_TYPE>
void redBlackTree<DATA_TYPE>::insertNode(std::unique_ptr<redBlackTreeNode<DATA_TYPE>> node)
{
    if (node != nullptr)
    {
        /* Insert helper starts at root and recursively adds the node and adjusts the tree as
         * necessary, returning the new root
         */
        root_ = insertHelper(this->root_, node);
        root_->color() = color::BLACK; //root should always be black
    }
    
    #ifdef VERIFY_RBTREE
    verify_properties(); //verify that the tree isn't broken 
    #endif
} 

template <class DATA_TYPE>
redBlackTree<DATA_TYPE>::~redBlackTree()
{
    #ifdef DBG_RBTREE
    cout << "RBTree destructor" << endl;
    #endif
}
