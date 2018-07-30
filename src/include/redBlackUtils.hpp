#pragma once

#include <cstdint>

constexpr static uint_fast8_t LINK_SIZE = 2;

enum class color
{
    BLACK = -1,
    INVALID = 0,
    RED = 1
};

//used to verbose array offset in link
enum class direction
{
    LEFT = -1,
    NONE = 0, //this will cause errors if used it exists only for initializaition purposes
    RIGHT = 1,
};

//This lets us swap colors in a one liner
inline color invertColor(color c) { return c == color::BLACK ? color::RED : color::BLACK; }

inline direction oppDir(direction d)
{
    return d == direction::LEFT ? direction::RIGHT : direction::LEFT;
}
