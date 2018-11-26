#include "identifier.hpp"
#include "hash.h"

identifier::identifier(secStr& key)
{
    if (key.size() > 0)
    {
        skeinHash(
            key.byteStr(),
            key.size(),
            reinterpret_cast<uint8_t*>(id_.data()),
            (id_.size() * sizeof(id_data_t)));
    }
}
