#ifndef TESTREDBLACKTREE_HPP
#define TESTREDBLACKTREE_HPP

#include "gtest/gtest.h"
#include "mockNodeValue.hpp"
#include "src_header/redBlackTree.hpp"
#include "src_header/secureString.hpp"

class unitTestRedBlackTree : public ::testing::Test
{
    protected:
  
    redBlackTree tree_;

    /************************************
    * Test fixture set up and tear down *
    ************************************/
    virtual void SetUp();
    virtual void TearDown(); 
};

#endif
