#pragma once

#include "constants.h"

#include <array>
#include <cstdint>

typedef std::array<uint64_t, ID_WORD_SIZE> identifier_t;

/*
 * This object is essentially a giant unsigned integer used to store unique identifiers
 * and provide operators to compare them.
 */
class identifier
{
    public:
    identifier() = default;

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

    inline identifier_t& data() const
    {
      return id_;
    }
    
    private:

    mutable identifier_t id_{};
};
