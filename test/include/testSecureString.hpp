#pragma once

#include <cstring> //strlen(), memcmp()
#include <string> //std::string class
#include "gtest/gtest.h" //testing::Test class
#include "identifier.hpp"
#include "secureString.hpp"
#include "testNode.hpp"

class unitTestSecureString : public ::testing::Test
{
    /* Setup and TearDown are unused */
};
