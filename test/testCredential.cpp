#include <array>
#include <gtest/gtest.h>
#include "constants.h"
#include "credential.hpp"
#include "masterKey.hpp"

using std::array;

class CredentialTest : public ::testing::Test
{
    public:
        void SetUp() override
        {
            // we aren't testing the crypto here so an empty salt is ok
            array<uint64_t, SALT_WORD_SIZE> salt{};
            master_key_.setSalt(salt.data())
        }

        void TearDown() override
        {
            master_key_.clearKey();
            master_key_.clearSalt();
        }

    private:
    masterKey master_key_{};
};
