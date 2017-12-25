#pragma once

#ifdef __cplusplus
extern "C"
{
#endif /*end __cplusplus*/

#define LINK_SIZE 2

typedef enum
{
    BLACK = -1,
    INVALID,
    RED = 1
} color;

//used to verbose array offset in link
typedef enum
{
    NONE = -1, //this will cause errors if used it exists only for initializaition purposes
    LEFT = 0,
    RIGHT = 1,
} rb_direction;

//This lets us swap colors in a one liner
inline color invertColor(color c) { return c == BLACK ? RED : BLACK; }

inline rb_direction oppDir(rb_direction d) { return d == LEFT ? RIGHT : LEFT; }

#ifdef __cplusplus
}
#endif /*end __cplusplus*/
