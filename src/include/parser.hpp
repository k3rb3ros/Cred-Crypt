#pragma once

#include <iostream> //std::istream class
#include <memory> //std::unique_ptr
#include <stddef.h> //size_t
#include <string.h> //strncmp()
#include <vector> //std::vector container
#include "cJSON.h" //cJSON parser
#include "credential.hpp" //credential class
#include "masterKey.hpp" //masterKey class
#include "nodeValueBase.hpp" //nodeValueBase class
#include "secureString.hpp" //secStr class

using std::ios_base;
using std::istream;
using std::make_shared;
using std::shared_ptr;
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
    parser(const masterKey* mk);

    /*************
    * destructor *
    *************/
    ~parser();

    /*****************
    * public methods *
    *****************/
    bool errorsOccured();

    size_t numCredentialsParsed();

    vector<shared_ptr<secStr>> getErrors();

    vector<credential*>& getParsedCredentials();

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
    const masterKey* mk_;
    unique_ptr<char[]> input_;
    cJSON* output_;
    vector<credential*> creds_;
    vector<shared_ptr<secStr>> errors_;

    /******************
    * private methods *
    ******************/
    bool isCredential(cJSON* obj);

    void parseInternal();
};
