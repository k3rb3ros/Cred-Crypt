#pragma once

#include <cstddef> //size_t
#include <cstring> //strncmp()
#include <iostream> //std::istream class
#include <memory> //std::unique_ptr
#include <vector> //std::vector container
#include "cJSON.h" //cJSON parser
#include "credential.hpp" //credential class
#include "masterKey.hpp" //masterKey class
#include "secureString.hpp" //secStr class

using std::ios_base;
using std::istream;
using std::move;
using std::unique_ptr;
using std::vector;

#ifdef DBG_PARSER
using std::cout;
using std::endl;
#endif

class parser
{
    public:

    /***************
    * Constructors *
    ***************/
    parser() = delete;

    explicit parser(const masterKey& mk, vector<unique_ptr<credential>>& cred_container);

    /*************
    * destructor *
    *************/
    ~parser();

    /*****************
    * public methods *
    *****************/
    bool errorsOccured();

    size_t numCredentialsParsed();

    vector<secStr> getErrors();

    void clear();

    void parse();

    /*******************
    * public operators *
    *******************/
    friend istream& operator>>(istream& in, parser& rhs);
    friend secStr& operator>>(secStr& lhs, parser& rhs);

    private:
    /***************
    * private data *
    ***************/
    const masterKey& mk_;
    cJSON* output_{nullptr};
    unique_ptr<char[]> input_{};
    vector<unique_ptr<credential>>& creds_;
    vector<secStr> errors_{};

    /******************
    * private methods *
    ******************/
    bool isCredential(cJSON* obj);

    void parseInternal();
};
