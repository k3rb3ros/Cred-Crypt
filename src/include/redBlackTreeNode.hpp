#pragma once

#include "constants.h" //ID_WORD_SIZE
#include "redBlackStructs.h"
#include "nodeBase.hpp" //nodeBaseClass
#include "util.h" //compareWordBuff()

#ifdef DBG_RBTREE
    #include <iostream>
    using std::cout;
    using std::endl;
#endif

class redBlackTreeNode: public nodeBase
{
    public:

    //CTOR
    explicit redBlackTreeNode() : nodeBase(), color_(BLACK), link_ { nullptr, nullptr }
    { /*nop*/ }

    explicit redBlackTreeNode(nodeValueBase* value) : nodeBase(value), color_(RED), link_ { nullptr, nullptr }
    { /*nop*/ }

    inline bool operator ==(redBlackTreeNode& rhs)
    { return &rhs == this; }

    inline bool operator <(redBlackTreeNode& rhs)
    { return (compareWordBuff(this->getID(), rhs.getID(), ID_WORD_SIZE) < 0); }

    inline bool operator >(redBlackTreeNode& rhs)
    { return (compareWordBuff(this->getID(), rhs.getID(), ID_WORD_SIZE) > 0); }

    /*************************
    * Node traversal methods *
    *************************/
    inline ::color& color() { return color_; }
    inline nodeValueBase* value() { return value_.get(); }
    inline redBlackTreeNode*& left() { return link_[LEFT]; }
    inline redBlackTreeNode** link() { return &link_[0]; }
    inline redBlackTreeNode*& right() { return link_[RIGHT]; }

    inline uint64_t* getID() { return (value_ != nullptr) ? value_->getID() : nullptr; }

    //DTOR
    ~redBlackTreeNode()
    {
        #ifdef DBG_RBTREE
        cout << "Destructor called on redBlackTreeNode" << endl;
        #endif
    }

    private:

    /******************
    * Private members *
    ******************/
    //value_ is stored by base class
    ::color color_;
    redBlackTreeNode* link_[LINK_SIZE];
};
