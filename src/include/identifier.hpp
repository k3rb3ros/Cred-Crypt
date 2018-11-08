#pragma once

#include "constants.h"
#include "secureString.hpp"

#include <array>
#include <cstdint>

using identifier_t = std::array<uint64_t, ID_WORD_SIZE>;
using id_data_t = uint64_t;

/*
 * This object is essentially a giant unsigned integer used to store unique identifiers
 * and provide operators to compare them.
 */
class identifier
{
    public:
    // create an empty identifier to be filled by the consumer
    identifier() = default;

    // create an identifier skein512 hashed from the key
    identifier(secStr& key);

    // used for testing
    explicit identifier(const uint64_t id) { id_[0] = id; }

    inline bool operator ==(identifier &rhs) const
    {
      for (uint_fast8_t i=0; i<id_.size(); ++i)
      {
        if (id_[i] != rhs.id_[i]) { return false; }
      }

      return true;
    };

    inline bool operator <(identifier &rhs) const
    {
      bool is_less_than = false;

      for (uint_fast8_t i=0; i<id_.size(); ++i)
      {
        if (id_[i] < rhs.id_[i])
        {
          is_less_than = true;
          break;
        }
        else if (id_[i] < rhs.id_[i])
        {
          break;
        }
      }

      return is_less_than;
    };

    inline bool operator <(const identifier &rhs) const
    {
      bool is_less_than = false;

      for (uint_fast8_t i=0; i<id_.size(); ++i)
      {
        if (id_[i] < rhs.id_[i])
        {
          is_less_than = true;
          break;
        }
        else if (id_[i] < rhs.id_[i])
        {
          break;
        }
      }

      return is_less_than;
    };

    inline bool operator >(identifier &rhs) const
    {
      bool is_greater_than = false;

      for (uint_fast8_t i=0; i<id_.size(); ++i)
      {
        if (id_[i] > rhs.id_[i])
        {
          is_greater_than = true;
          break;
        }
        else if (id_[i] > rhs.id_[i])
        {
          break;
        }
      }

      return is_greater_than;
    }

    inline id_data_t* data() const
    {
      return id_.data();
    }

    private:

    mutable identifier_t id_{};
};
