#pragma once

#include "identifier.hpp"

#include <vector>
#include <memory>
#include <map>
#include <utility>

/*
 * This class provides a searchable storage source for arbitrary objects
 */

using std::map;
using std::move;
using std::unique_ptr;
using std::vector;

template <class DATA_TYPE>
class registry
{
    public:
    registry() = default;

    inline bool erase(const identifier& id)
    {
        const auto delete_me = data_.find(id);
        if (delete_me != data_.end())
        {
            data_.erase(delete_me);
            return true;
        }
        return false;
    }

    inline bool exists(const identifier& id) const
    {
        return (data_.find(id) != data_.end());
    }

    DATA_TYPE* search(const identifier& id)
    {
        DATA_TYPE* result = nullptr;

        const auto search = data_.find(id);
        if (search != data_.end())
        {
            result = &*(search->second);
        }

        return result;
    }

    size_t size() const { return data_.size(); }

    vector<DATA_TYPE*> traverse() const
    {
        vector<DATA_TYPE*> nodes(data_.size(), nullptr);

        size_t index = 0;
        for (auto &n: data_)
        {
            nodes[index++] = n.second.get();
        }

        return nodes;
    }

    inline void insert_data(unique_ptr<DATA_TYPE> data)
    {
        data_[data->get_id()] = move(data);
    }

    private:

    map<identifier, unique_ptr<DATA_TYPE>> data_{};
};
