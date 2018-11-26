#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <type_traits>

template<typename ARRAY_T>
void clearArray(ARRAY_T& array)
{
    array.fill(0);
}

template<typename BUFFER_T>
void clearBuffer(BUFFER_T* bfr, const size_t byte_size)
{
    static_assert(std::is_pod<BUFFER_T>::value, "clearBuffer() can only operate on POD data types.");
    std::fill(bfr, (bfr+byte_size), 0);
}
