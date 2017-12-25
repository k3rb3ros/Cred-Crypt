#ifndef MOCKNODEVALUE_HPP
#define MOCKNODEVALUE_HPP

#include <stdint.h> //uint64_t
#include <string> //std::string std::to_string
#include <sstream> //std::ssstream
#include "src_header/constants.h" //ID_WORD_SIZE
#include "src_header/hash.h" //skeinHash()
#include "src_header/nodeValueBase.hpp" //nodeValueBase

using std::string;
using std::stringstream;

class mockNodeValue : public nodeValueBase
{
    private:
    uint64_t val_;
    uint64_t id_[ID_WORD_SIZE];

    public:
    /**************
    * Constructor *
    **************/
    mockNodeValue(uint64_t val);

    bool operator ==(nodeValueBase &rhs) const;
    bool operator <(nodeValueBase &rhs);
    bool operator >(nodeValueBase &rhs);

    uint64_t* getID();

    uint64_t value() const;
};

#endif
