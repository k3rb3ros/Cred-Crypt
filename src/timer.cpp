#include "include/timer.hpp"

timer::timer(duration<unsigned int>& duration):
    bkgrd_thread_(runTimer, ref(args_))
{
    args_.s_clock = &clock_;
    args_.s_timeout = &timeout_;
    args_.s_keys = &keys_;
    args_.s_thread = &bkgrd_thread_;
    duration_ = duration;
    timeout_ = (clock_.now() + duration);
}

timer::~timer()
{
    //tell the thread to terminate and wait for it to finish
    args_.s_running = false;
    if (args_.s_thread != nullptr)
    {
        args_.s_thread->join();
    }
}

//register the given void() function
bool timer::registerKey(keyBase* key)
{
    size_t s = keys_.size();
    keys_.push_back(key);

    return (keys_.size() == s+1);
}

//unregister the given void() function
bool timer::unregisterKey(keyBase* key)
{
    bool unreged = false;

    if (keys_.size() > 0)
    {
        for (vector<keyBase*>::iterator it = keys_.begin();
             it!=keys_.end();
             ++it)
        {
            if (*it == key)
            {
                keys_.erase(it);
                unreged = true;
                break;
            }
        }
    }

    return unreged;
}

void timer::reset()
{
    timeout_ = (clock_.now() + duration_);
    args_.s_triggered = false;
    args_.s_ticking = true;
}

void timer::start()
{
    args_.s_ticking = true;
}

void timer::stop()
{
    args_.s_ticking = false;
}

//This runs in the background thread
void runTimer(time_s& args)
{
    while (args.s_running)
    {
        if (args.s_ticking)
        {
            if (!args.s_triggered &&
                args.s_clock->now() >= *args.s_timeout) //check if the timeout time has elapsed
            {
                if (args.s_keys->size() > 0)
                {
                    for (auto &it: *(args.s_keys))
                    {
                        it->clearKey();
                    }
                }
                args.s_triggered = true;
            }
        }
        sleep_for(milliseconds(500));
    }
}
