#pragma once

#include <chrono> //seconds class, stead_clock class
#include <memory> //std::unique_ptr
#include <thread> //thread class
#include <vector> //std::vector container
#include "constants.h"
#include "keyBase.hpp" //keyBase class template

using std::chrono::duration;
using std::chrono::milliseconds;
using std::chrono::steady_clock;
using std::ref;
using std::this_thread::sleep_for;
using std::thread;
using std::unique_ptr;
using std::vector;

struct time_s
{
    bool s_running{true};
    bool s_ticking{false};
    bool s_triggered{false};
    steady_clock* s_clock{nullptr};
    steady_clock::time_point* s_timeout{nullptr};
    thread* s_thread{nullptr};
    vector<keyBase<KEY_WORD_SIZE>*>* s_keys{nullptr};
};

/*
 * The timer class exists to provide a mechanism to clear the master key (or any other)
 * when a given amount of time passes
 */
class timer
{
    public:
    /**************
    * Public Data *
    **************/
    time_s args_{};

    explicit timer(duration<unsigned int>& timeout);
    ~timer();

    /*****************
    * Public Members *
    ******************/
    bool registerKey(keyBase<KEY_WORD_SIZE>* key);

    bool unregisterKey(keyBase<KEY_WORD_SIZE>* key);

    void reset();

    void start();

    void stop();

    private:

    /***************
    * Private Data *
    ****************/
    steady_clock clock_{};
    duration<unsigned int> duration_{};
    steady_clock::time_point timeout_{};
    vector<keyBase<KEY_WORD_SIZE>*> keys_{};
    thread bkgrd_thread_{};

    /***************
    * Constructors *
    ***************/
    //disable default ctor
    timer() = delete;
};

//thread function
void runTimer(time_s& args);
