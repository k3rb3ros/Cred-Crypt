#include "include/secureString.hpp"

using std::bad_alloc;
using std::copy;
using std::fill;
using std::make_unique;
using std::out_of_range;
using std::swap;

secStr::secStr()
{}

secStr::secStr(const char* c_str)
{
    if (c_str != nullptr)
    {
        // get the size of the c_str
        while (c_str[size_] != '\0')
        {
            size_++;
        }

        if (size_ > 0)
        {
            // allocate storage of the size of the c_str passed in
            str_ = make_unique<uint8_t[]>(size_ + 1);
            // copy the c_str to the byte array
            copy(c_str, (c_str + size_), str_.get());
            // null terminate the string
            str_[size_] = 0;
        }
    }
}

secStr::secStr(const uint8_t* bytes, const size_t size) : size_(size)
{
    if (bytes != nullptr && size > 0)
    {
        str_ = make_unique<uint8_t[]>(size);
        copy(bytes, (bytes + size), str_.get());
    }
}

secStr::secStr(const string str) : size_(str.size())
{
    if (size_ > 0)
    {
        str_ = make_unique<uint8_t[]>(size_);
        copy(str.begin(), str.end(), str_.get());
    }
}

/* copy constructor */
secStr::secStr(const secStr &rhs) : size_(rhs.size_)
{
    if (size_ > 0)
    {
        str_ = make_unique<uint8_t[]>(size_);
        copy(rhs.str_.get(), (rhs.str_.get() + rhs.size_), str_.get());
    }
}

int_fast8_t secStr::compare(const char* c_str) const
{
    size_t sz = 0;

    while (sz < size_ && c_str[sz] != '\0') //iterate through the strings while they match
    {
        if (this->str_[sz] < c_str[sz]) { return -1; }
        if (this->str_[sz] > c_str[sz]) { return 1; }
        ++sz;
    }

    // at this point the strings are either the same string or the same up until this point but 2 different lengths
    // check if the strings differ in size
    if (sz > size_) { return -1; } //c_str longer then secStr
    if (sz < size_) { return 1; } //secStr longer then c_str

    return 0;
}

int_fast8_t secStr::compare(const secStr &str) const
{
    //get the shorter of the two string lengths, if they are the same length it doesn't matter
    size_t len_lim = size_ <= str.size_ ? size_ : str.size_;

    for (size_t sz=0; sz<len_lim; ++sz)
    {
        if (str_[sz] < str.str_[sz]) { return -1; }
        if (str_[sz] > str.str_[sz]) { return 1; }
    }

    if (str.size_ > size_) { return -1; } //string we are comparing to is longer
    else if (str.size_ < size_) { return 1; } //string we are comparing to is shorter

    return 0;
}

int_fast8_t secStr::compare(const string &str) const
{
    //get the shorter of the two string lengths, if they are the same length it doesn't matter
    size_t len_lim = size_ <= str.size() ? size_ : str.size();

    for (size_t sz=0; sz<len_lim; ++sz)
    {
        if (str_[sz] < str_[sz]) { return -1; }
        if (str_[sz] > str_[sz]) { return 1; }
    }

    if (str.size() > size_) { return -1; }
    else if (str.size() < size_) { return 1; }

    return 0;
}

bool secStr::operator ==(const secStr &rhs) const
{
    if (&rhs == this) { return true; } //same object is always equal
    else if (size_ != rhs.size_) { return false; } //different sized strings are never equal

    //otherwise we compare every byte in the string if they all match then the strings are equal
    for (size_t sz=0; sz<size_; ++sz)
    {
        if (str_[sz] != rhs.str_[sz]) { return false; }
    }

    return true;
}

bool secStr::operator <(const secStr& rhs) const
{
    return (this->compare(rhs) < 0);
}

bool secStr::operator >(const secStr& rhs) const
{
    return (this->compare(rhs) > 0);
}

uint8_t& secStr::operator [](const size_t sz)
{
    if (sz >= size_) { throw out_of_range("Index out of range of string requested"); }

    return str_[sz];
}

/*************************************
* Copy assignment operator overloads *
*************************************/
secStr& secStr::operator =(const secStr& rhs)
{
    if (this != &rhs)
    {
        if (size_ != rhs.size_) // storage cannot be reused (e.g) diff sizes)
        {
            if (str_ != nullptr && size_ > 0)
            {
                fill(str_.get(), (str_.get() + size_), 0);
                size_ = 0;
            }

            size_ = rhs.size_;
            str_ = unique_ptr<uint8_t[]>(new uint8_t[rhs.size_+1]());
        }
    }

    //Copy the string
    for (size_t sz=0; sz<size_; ++sz)
    {
        str_[sz] = rhs.str_[sz];
    }

    return *this;
}

secStr& secStr::operator =(const string& rhs)
{
    if (size_ != rhs.size()) //resize the string
    {
        if (str_ != nullptr && size_ > 0)
        {
            fill(str_.get(), (str_.get() + size_), 0);
            size_ = 0;
        }

        size_ = rhs.size();
        str_ = unique_ptr<uint8_t[]>(new uint8_t[size_+1]());
    }

    //Copy the string
    for (size_t sz=0; sz<size_; ++sz)
    {
        str_[sz] = rhs[sz];
    }

    return *this;
}

secStr& secStr::operator =(string& rhs)
{
    if (size_ != rhs.size()) //resize the string
    {
        if (str_ != nullptr && size_ > 0)
        {
            fill(str_.get(), (str_.get() + size_), 0);
            size_ = 0;
        }

        size_ = rhs.size();
        str_ = unique_ptr<uint8_t[]>(new uint8_t[size_+1]());
    }

    //Copy the string
    for (size_t sz=0; sz<size_; ++sz)
    {
        str_[sz] = rhs[sz];
    }

    return *this;
}

//Move assignment
secStr& secStr::operator =(secStr&& rhs)
{
    assert(this != &rhs);
    //delete the existing strings contents and swap the str_ pointer with the new one
    if (str_ != nullptr && size_ > 0)
    {
        fill(str_.get(), (str_.get() + size_), 0);
    }

    //swap the pointers to the content and adjust the size
    swap(str_, rhs.str_);
    rhs.str_ = nullptr;
    size_ = rhs.size_;
    rhs.size_ = 0;

    return *this;
}

/********************
* External to class *
********************/
secStr operator +(secStr &lhs, secStr &rhs)
{
    size_t l_size = lhs.size();
    size_t r_size = rhs.size();

    unique_ptr<uint8_t[]> concat(new uint8_t[l_size + r_size]());

    if (l_size > 0 && r_size > 0)
    {
        for (size_t s=0; s<(l_size+r_size); ++s)
        {
            if (s < l_size)
            {
                concat[s] = lhs[s];
            }
            else
            {
                assert(s >= l_size);
                concat[s] = rhs[s-l_size];
            }
        }
    }
    else if (l_size > 0 || r_size > 0)
    {
        secStr* side = (l_size != 0) ? &lhs : &rhs;
        for (size_t s=0; s<side->size(); ++s)
        { concat[s] = (*side)[s]; }
    }

    return secStr(concat.get(), (l_size+r_size));
}

istream& getline(istream& is, secStr& str, const uint8_t delim)
{
    size_t index = 0;
    size_t bfr_size = 128;
    /* reallocating the temp buffer the c way seemed like a better solution then re-inventing
    * the wheel
    */
    uint8_t* bfr = (uint8_t*)calloc(bfr_size, sizeof(uint8_t));

    //get the line
    while (is && (is.peek() != delim))
    {
       bfr[index++] = is.get();
       if (index == bfr_size -1)
       {
           bfr_size *= 2;
           bfr = (uint8_t*)realloc(bfr, bfr_size);
       }
    }
    is.get(); //eat the newline character

    str = secStr(bfr, index);
    fill(bfr, (bfr + bfr_size), 0);
    free(bfr);

    return is;
}

secStr secStr::substr(const size_t start, const size_t len) const
{
    if (len > 0)
    {
        if (start > size_-1) { throw out_of_range("Start offset"); }
        if ((start+len) > size_) { throw out_of_range("Length"); }

        //create an array to store the substring
        unique_ptr<uint8_t[]> sub_str(new uint8_t[len]());

        //copy the substring from the main string to an array
        for (size_t i=0; i<len; ++i)
        {
            sub_str[i] = str_[(start+i)];
        }

        secStr subStr(sub_str.get(), len);

        return subStr;
    }

    return secStr();
}

size_t secStr::size() const { return size_; }

uint8_t* secStr::byteStr() { return (size_ == 0) ? nullptr : str_.get(); }

vector<secStr> secStr::split(const uint8_t delim = '\n') const
{
    size_t start = 0;
    size_t offset = 0;
    vector<secStr> split;

    while (offset < size_)
    {
        //move the start index until it is not pointing at an instance of delim (start offset here)
        while (str_[start] == delim && start < (size_)) { offset = ++start; }
        //move offset until its pointing to the next instance of delim
        while (str_[offset] != delim && offset < (size_)) { offset++; }
        //split the substring and store it
        split.push_back(substr(start, (offset-start)));
        start = offset++;
    }

    return split;
}

vector<secStr> secStr::splitWQuotes(const uint8_t delim) const
{
    // escaped double quotes \" do not get split on like regular double quotes
    assert(delim != '"'); //doesn't work for splititng on " since they are handled differently
    size_t start = 0;
    size_t offset = 1;
    splitState state = splitState::DEFAULT;
    vector<secStr> split;

    if (size_ < 2) { return split; } //we can't split an array with > 2 characters in it

    while (offset < size_)
    {
        switch (state)
        {
            case splitState::DEFAULT:
                // an instance of delim
                if (str_[start] == delim ||
                   (start == 0 && str_[start] != '"'))
                {
                    if (str_[start] == delim) { ++start; } //eat the delim character
                    state = splitState::IN_WORD;
                    continue;
                } // a non escaped double quote
                else if ((start == 0 && str_[start] == '"') ||
                         (str_[start] == '"' && str_[start-1] != '\\'))
                {
                    if (str_[start] == '"') { ++start; } //eat the " character
                    state = splitState::IN_DB_QUOTE;
                    continue;
                }
            break;
            case splitState::IN_DB_QUOTE:
                // advance until we find another non escaped dbl quote or the end of the string
                while (offset < size_ &&
                      (((str_[offset] != '"')) ||
                      (str_[offset] == '"' && str_[offset-1] == '\\')))
                { offset++; }

                // split the substring
                split.push_back(substr(start, (offset-start)));
                if (str_[offset] == '"') { ++offset; }; //eat the trailing "
                state = splitState::DEFAULT;
            break;
            case splitState::IN_WORD:
                // advance until we find delim, an unescaped double quote or the end of the string
                while (offset < size_ &&
                       str_[offset] != delim &&
                       (str_[offset] != '"' || (offset > 0 && str_[offset] == '"' && str_[offset-1] == '\\')))
                {
                    offset++;
                } // end while

                if ((str_[offset] == '"' && offset == 0) ||
                (str_[offset] == '"' && str_[offset-1] != '\\'))
                {
                    ++offset; //eat the the trailing "
                    state = splitState::IN_DB_QUOTE;
                }
                else if (str_[offset] == delim)
                {
                    state = splitState::DEFAULT;
                }

                if (str_[start] != delim && str_[start] != '"')
                {
                    split.push_back(substr(start, (offset-start)));
                }
            default:
            break;
        } //end switch

        start = offset++;
    } //end while

    return split;
}

/********************
* External to class *
********************/
bool operator <(secStr& lhs, secStr& rhs)
{
    bool lt = false;
    size_t min_size = (lhs.size() < rhs.size()) ? lhs.size() : rhs.size();

    for (size_t i=0; i<min_size; ++i)
    {
        if (lhs[i] < rhs[i])
        {
            lt = true;
            break;
        }
        else if (lhs[i] > rhs[i]) { break; }
    }

    return lt;
}

/********************
* External to class *
********************/
istream& operator >>(istream& is, secStr &rhs)
{
    if (is)
    {
        size_t start = is.tellg();
        // clear the existing contents of the string
        fill(rhs.byteStr(), (rhs.byteStr() + rhs.size_), 0);
        is.seekg(0, is.end);
        size_t end = is.tellg();
        is.seekg(start);

        rhs.str_ = unique_ptr<uint8_t[]>(new uint8_t[end-start]());
        rhs.size_ = (end-start);

        for (size_t sz=0; sz<(end-start); ++sz)
        {
            if (is.good()) { is >> rhs[sz]; }
        }
    }

    return is;
}

ostream& operator <<(ostream &os, const secStr &str)
{
    for (size_t sz=0; sz<str.size_; ++sz) { os << str.str_[sz]; }

    return os;
}

ostream& operator <<(ostream &os, secStr &str)
{
    for (size_t sz=0; sz<str.size_; ++sz) { os << str.str_[sz]; }

    return os;
}

secStr::~secStr() noexcept
{
    if (str_.get() != nullptr)
    {
        fill(str_.get(), (str_.get() + size_), 0);
    }
 }
