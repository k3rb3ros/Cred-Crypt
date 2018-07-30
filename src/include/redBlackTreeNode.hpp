#pragma once

#include "constants.h" //ID_WORD_SIZE
#include "redBlackUtils.hpp"

#include <memory>
#include <utility>

#ifdef DBG_RBTREE
    #include <iostream>
    using std::cout;
    using std::endl;
#endif

template <class DATA_TYPE>
class redBlackTreeNode
{
    public:

    //constructors
    explicit redBlackTreeNode<DATA_TYPE>() = default;

    explicit redBlackTreeNode<DATA_TYPE>(std::unique_ptr<redBlackTreeNode<DATA_TYPE>> data):
        data_{std::move(data)}
    { /*nop*/ }

    //destructor
    ~redBlackTreeNode<DATA_TYPE>()
    {
        #ifdef DBG_RBTREE
        cout << "Destructor called on redBlackTreeNode" << endl;
        #endif
    }

    inline bool operator ==(redBlackTreeNode<DATA_TYPE>& rhs)
    { return data_ == rhs.data_; }

    inline bool operator !=(redBlackTreeNode<DATA_TYPE>& rhs)
    { return !(data_ == rhs.data_); }

    inline bool operator <(redBlackTreeNode<DATA_TYPE>& rhs)
    { return data_ < rhs.data_; }

    inline bool operator >(redBlackTreeNode<DATA_TYPE>& rhs)
    { return data_ > rhs.data_; }

    /*************************
    * Node traversal methods *
    *************************/
    inline ::color& color() { return color_; }
    // TODO fix me
    inline redBlackTreeNode<DATA_TYPE>*& left() { return link_[direction::LEFT]; }
    inline redBlackTreeNode<DATA_TYPE>** link() { return &link_[0]; }
    inline redBlackTreeNode<DATA_TYPE>*& right() { return link_[direction::RIGHT]; }

    /***************
     * Data Access *
     **************/
    inline std::unique_ptr<redBlackTreeNode<DATA_TYPE>> getData()
    { return std::move(data_); } 

    inline void setData(std::unique_ptr<redBlackTreeNode<DATA_TYPE>> new_data)
    { data_ = std::move(new_data); }

    private:

    /******************
    * Private members *
    ******************/
    std::unique_ptr<DATA_TYPE> data_{nullptr};
    ::color color_{::color::BLACK};
    std::unique_ptr<redBlackTreeNode<DATA_TYPE>> link_[LINK_SIZE] {nullptr, nullptr};
};
