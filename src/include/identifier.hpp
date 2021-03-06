#pragma once

#include "constants.h"
#include "secureString.hpp" //secStr class

#include <algorithm> //std::equal
#include <array> //std::array
#include <cstdint> // uint_xx types

using id_data_t = uint64_t;
using identifier_t = std::array<id_data_t, ID_WORD_SIZE>;

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
    explicit identifier(const id_data_t id) { id_[0] = id; }

    inline bool operator ==(identifier &rhs) const
    {
      return std::equal(id_.begin(), id_.end(), rhs.id_.begin());
    };

    inline bool operator ==(const identifier &rhs) const
    {
      return std::equal(id_.begin(), id_.end(), rhs.id_.begin());
    };

    inline bool operator <(identifier &rhs) const
    {
      bool is_less_than = false;

      // find the first index where the two indexes that differ (if any)
      auto mismatch = std::mismatch(id_.begin(), id_.end(), rhs.id_.begin());

      // compare that at the mismatch lhs < rhs
      if (mismatch.first != id_.end() && *mismatch.first < *mismatch.second)
      {
          is_less_than = true;
      }

      return is_less_than;
    };

    inline bool operator <(const identifier &rhs) const
    {
      bool is_less_than = false;

      // find the first index where the two indexes that differ (if any)
      auto mismatch = std::mismatch(id_.begin(), id_.end(), rhs.id_.begin());

      // compare that at the mismatch lhs < rhs
      if (mismatch.first != id_.end() && *mismatch.first < *mismatch.second)
      {
          is_less_than = true;
      }

      return is_less_than;
   };

    inline bool operator >(identifier &rhs) const
    {
      bool is_greater_than = false;

      // find the first index where the two indexes that differ (if any)
      auto mismatch = std::mismatch(id_.begin(), id_.end(), rhs.id_.begin());

      // compare that at the mismatch lhs > rhs
      if (mismatch.first != id_.end() && *mismatch.first > *mismatch.second)
      {
          is_greater_than = true;
      }

      return is_greater_than;
    }

    inline id_data_t* data() const
    {
      return id_.data();
    }

    constexpr size_t byte_size() const
    {
      return (id_.size() * sizeof(id_data_t));
    }

    constexpr size_t word_size() const
    {
      return id_.size();
    }

    private:

    mutable identifier_t id_{};
};
