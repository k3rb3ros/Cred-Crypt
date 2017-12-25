#pragma once

/*
* This is a string class analagous to std::string but with less memory overhead and
* less functionality
* The benefit being the secureStrings zero fill their string content on destruction,
* can handle the full byte range of characters and do not have to be null terminated.
* Secure Strings are stored internally as uint8_t arrays they make no guarantee that internal
* characters will be in the ascii range and non NULL.
* This allows encrypted text to be stored in Secure Strings.
* It also prevents c_str methods from being able to be used with secure strings or SecureString
* from being converted (directly) into c_str(s).
*/

#include <cassert> //assert()
#include <iostream> //std::ostream class
#include <memory> //std::unique_ptr
#include <stdexcept> //std::out_of_range exception
#include <string> //std::string class
#include <utility> //std::exchange class, std::swap
#include <vector> //std::vector container
#include "stdint.h" //uintxx_t types
#include "util.h" //clearBuff(), resize()

using std::bad_alloc;
using std::istream;
using std::make_shared;
using std::ostream;
using std::out_of_range;
using std::shared_ptr;
using std::string;
using std::swap;
using std::unique_ptr;
using std::vector;

enum splitState
{
    DEFAULT,
    IN_DB_QUOTE,
    IN_WORD
};

class secStr
{
    private:
    /***************
    * private data *
    ***************/
    size_t size_;
    unique_ptr<uint8_t[]> str_;

    void stripEscapedQuotes(secStr &str);

    public:
    /***************
    * constructors *
    ***************/
    explicit secStr(); //empty string
    explicit secStr(const char* c_str); //copy from c_str
    explicit secStr(const uint8_t* c_str, size_t size); //copy from byte array
    explicit secStr(const string); //copy from std::string
    secStr(const secStr &rhs); //copy from secStr

    /*********************
    * comparison methods *
    *********************/
    int_fast8_t compare(const char* c_str) const; //c_string
    int_fast8_t compare(const secStr &str) const; //secure string
    int_fast8_t compare(const string &str) const; //std::string

    /***********************
    * comparison operators *
    ***********************/
    bool operator ==(const secStr &rhs) const;
    bool operator <(const secStr &rhs) const;
    bool operator >(const secStr &rhs) const;

    /*******************
    * access operators *
    *******************/
    uint8_t& operator[](const size_t sz);

    /************************
    * modifcation operators *
    ************************/
    secStr& operator =(const secStr &rhs); //Copy assignment from const secStr
    secStr& operator =(string &rhs); //Copy assignment from secStr
    secStr& operator =(const string &rhs); //copy assignment from std::string
    secStr& operator =(secStr &&rhs); //Move assignment

    friend secStr operator +(secStr &lhs, secStr &rhs); //concatination

    /*****************
    * public methods *
    *****************/
    friend istream& getline (istream& is, secStr& str, const uint8_t delim);
    secStr substr(const size_t start, const size_t len) const;
    size_t size() const;
    uint8_t* byteStr();
    vector<shared_ptr<secStr>> split(const uint8_t delim) const;
    vector<shared_ptr<secStr>> splitWQuotes(const uint8_t delim) const;

    /************************************
    * out of class comparison overloads *
    ************************************/
    friend bool operator <(secStr &lhs, secStr &rhs);

    /*******************
    * stream overloads *
    *******************/
    friend istream& operator >>(istream &is, secStr &secStr);
    friend ostream& operator <<(ostream &os, const secStr &str);
    friend ostream& operator <<(ostream &os, secStr &str);

    /*************
    * destructor *
    *************/
    ~secStr() noexcept;
};
