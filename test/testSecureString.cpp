#include "include/testSecureString.hpp"

/* Constructor tests */
TEST(unitTestSecureString, DefaultInitIsEmpty)
{
    secStr dflt;

    ASSERT_EQ(dflt.size(), 0u);
    char* c_str = (char*)dflt.byteStr();
    ASSERT_STREQ(c_str, nullptr);
}

TEST(unitTestSecureString, DbQuoteInitIsEmpty)
{
    secStr empty("");

    ASSERT_EQ(empty.size(), 0u);
    uint8_t* null_byte = empty.byteStr();
    ASSERT_EQ(null_byte, nullptr);
}

TEST(unitTestSecureString, EmptyCStrInitIsEmpty)
{
    char ch = '\0';
    secStr empty(&ch);

    ASSERT_EQ(empty.size(), 0u);
    uint8_t* null_byte = empty.byteStr();
    ASSERT_EQ(null_byte, nullptr);
}

TEST(unitTestSecureString, EmptyStdStringInitIsEmpty)
{
    std::string init("");
    secStr empty(init);

    ASSERT_EQ(empty.size(), 0u);
    uint8_t* null_byte = empty.byteStr();
    ASSERT_EQ(null_byte, nullptr);
}

TEST(unitTestSecureString, EmptyByteInitIsEmpty)
{
    uint8_t null = '\0';
    secStr empty(&null, 0);

    ASSERT_EQ(empty.size(), 0u);
    uint8_t* null_byte = empty.byteStr();
    ASSERT_EQ(null_byte, nullptr);
}

TEST(unitTestSecureString, CStrInit)
{
    char phrase[] = "The quick red fox jumped over the lazy brown dog";
    secStr initTest(phrase);

    ASSERT_EQ(initTest.size(), 48u);
    uint8_t* byte_str = initTest.byteStr();

    for (size_t s=0; s<initTest.size(); ++s)
    {
        ASSERT_EQ(byte_str[s], phrase[s]);
    }
}

TEST(unitTestSecureString, StdStringInit)
{
    secStr cpy_cnst(string("Grum is awesome!"));

    ASSERT_EQ(cpy_cnst.size(), 16ULL);
    ASSERT_EQ(cpy_cnst[0], 'G');
    ASSERT_EQ(cpy_cnst[15], '!');
}

TEST(unitTestSecureString, ByteArrInitSavesContents)
{
    uint8_t phrase[] = "I can code in bed. If only I had something to say here while I do it...";
    secStr initTest(phrase, 71u);

    ASSERT_EQ(initTest.size(), 71u);
    uint8_t* byte_str = initTest.byteStr();

    for (size_t s=0; s<initTest.size(); ++s)
    {
        ASSERT_EQ(byte_str[s], phrase[s]);
    }
}

TEST(unitTestSecureString, StdStringInitSavesStrWOutNull)
{
    std::string phrase = "I am tired but I need to write unit tests.";
    secStr initTest(phrase);

    ASSERT_EQ(initTest.size(), phrase.size());
    uint8_t* byte_str = initTest.byteStr();

    for (size_t s=0; s<phrase.size(); ++s)
    {
        ASSERT_EQ(byte_str[s], phrase[s]);
    }
}

/* Operator tests */
TEST(unitTestSecureString, EQCmprOP)
{
    secStr same_str1("I don't want to get up early for work tomorrow.");
    secStr same_str2("I don't want to get up early for work tomorrow.");
    secStr diff_str("Hey asshole suck a bag of dicks");

    bool equal = (same_str1 == same_str2);
    ASSERT_TRUE(equal);

    bool not_equal = (same_str1 == diff_str);
    ASSERT_FALSE(not_equal);
}

/* compare tests */
TEST(unitTestSecureString, LTCmprOP)
{
    secStr one("1");
    secStr zed("0");
    secStr fourty_one("41");
    secStr fourty_two("42");
    secStr fourty_three("43");

    bool less_then = (zed < one);
    bool not_less_then = (one < zed);
    bool less_then_life = (fourty_one < fourty_two);
    bool not_less_then_life = (fourty_two < fourty_two);
    bool less_then_fourty_three = (fourty_two < fourty_three);

    ASSERT_TRUE(less_then);
    ASSERT_FALSE(not_less_then);
    ASSERT_TRUE(less_then_life);
    ASSERT_FALSE(not_less_then_life);
    ASSERT_TRUE(less_then_fourty_three);
}

TEST(unitTestSecureString, GTCmprOP)
{
    secStr one("1");
    secStr zed("0");
    secStr aa("AA");
    secStr zz("ZZ");

    bool greater_then = (one > zed);
    bool not_greater_then = (zed > one);
    bool greater_than = (zz > aa);
    bool not_greater_than = (aa > zz);
    bool not_greater_than2 = (zz > zz);

    ASSERT_TRUE(greater_then);
    ASSERT_FALSE(not_greater_then);
    ASSERT_TRUE(greater_than);
    ASSERT_FALSE(not_greater_than);
    ASSERT_FALSE(not_greater_than2);
}

TEST(unitTestSecureString, OPArrInd)
{
    secStr num_str("0123456789");
    uint8_t num_array[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

    //Test that array index returns the correct (known) value of a secureString
    ASSERT_EQ(num_str[0], num_array[0]);
    ASSERT_EQ(num_str[1], num_array[1]);
    ASSERT_EQ(num_str[2], num_array[2]);
    ASSERT_EQ(num_str[3], num_array[3]);
    ASSERT_EQ(num_str[4], num_array[4]);
    ASSERT_EQ(num_str[5], num_array[5]);
    ASSERT_EQ(num_str[6], num_array[6]);
    ASSERT_EQ(num_str[7], num_array[7]);
    ASSERT_EQ(num_str[8], num_array[8]);
    ASSERT_EQ(num_str[9], num_array[9]);
}

TEST(unitTestSecureString, OPArrBadIndThrowsOOR)
{
    secStr str("123");
    ASSERT_THROW(str[3], std::out_of_range);
}

TEST(unitTestSecureString, CopyAssignmentFromNullSecStr)
{
    const secStr empty("");
    secStr newStr = empty; //copy assignment

    ASSERT_EQ(newStr.size(), 0u);
    ASSERT_EQ(newStr.byteStr(), nullptr);
}


TEST(unitTestSecureString, CopyAssignmentFromNonNullSecStr)
{
    const secStr phrase("How now brown cow!");
    secStr newStr = phrase; //copy assignment
    std::string cpy("How now brown cow!");

    ASSERT_EQ(newStr.size(), 18u);

    for (size_t s=0; s<phrase.size(); ++s)
    {
        ASSERT_EQ(newStr[s], cpy[s]);
    }
}

TEST(unitTestSecureString, CopyAssignmentFromEmptyStdString)
{
    std::string empty("");
    secStr newStr;
    newStr = empty; //copy assignment

    ASSERT_EQ(newStr.size(), 0u);
    ASSERT_EQ(newStr.byteStr(), nullptr);
}

TEST(unitTestSecureString, CopyAssignmentFromStdString)
{
    std::string phrase("You Fucking Cunt!");
    secStr newStr;
    newStr = phrase; //copy assignment
    uint8_t* bytes = newStr.byteStr();

    ASSERT_EQ(newStr.size(), phrase.size());

    for (size_t s=0; s<phrase.size(); ++s)
    {
        ASSERT_EQ(bytes[s], (uint8_t)phrase[s]);
    }
}

TEST(unitTestSecureString, CopyAssignmentFromEmptyConstStdString)
{
    const std::string empty("");
    secStr newStr;
    newStr = empty; //copy assignment

    ASSERT_EQ(newStr.size(), 0u);
    ASSERT_EQ(newStr.byteStr(), nullptr);
}

TEST(unitTestSecureString, CopyAssignmentFromConstStdString)
{
    const std::string phrase("Now Listen Here!");
    secStr newStr;
    newStr = phrase; //copy assignment
    uint8_t* bytes = newStr.byteStr();

    ASSERT_EQ(newStr.size(), phrase.size());

    for (size_t s=0; s<phrase.size(); ++s)
    {
        ASSERT_EQ(bytes[s], (uint8_t)phrase[s]);
    }
}

TEST(unitTestSecureString, MoveAssignmentCopiesContents)
{
    uint8_t phrase[] = "I am poisoning your brain like a mushroom";
    secStr t1;

    ASSERT_EQ(t1.size(), 0u);
    ASSERT_EQ(t1.byteStr(), nullptr);

    t1 = secStr(phrase, 41u); //move assignment

    ASSERT_EQ(t1.size(), 41u);

    uint8_t* byte_str = t1.byteStr();
    for (size_t s=0; s<t1.size(); ++s)
    {
        ASSERT_EQ(byte_str[s], phrase[s]);
    }
}

TEST(unitTestSecureString, ConcatOfEmptyStringsEmpty)
{
    secStr s1;
    secStr s2;
    secStr concat = s1 + s2;

    ASSERT_EQ(concat.size(), 0u);
    ASSERT_EQ(concat.byteStr(), nullptr);
}

TEST(unitTestSecureString, ConcatOfTwoStrings)
{
    secStr s1("Bob ");
    secStr s2("is your uncle");
    secStr concat = s1 + s2;
    uint8_t* actual = concat.byteStr();
    uint8_t expected [17] =
    { 'B', 'o', 'b', ' ', 'i', 's', ' ', 'y', 'o', 'u', 'r', ' ', 'u', 'n', 'c', 'l', 'e' };

    ASSERT_EQ(concat.size(), 17u);
    for (size_t s=0; s<17; ++s)
    {
        ASSERT_EQ(actual[s], expected[s]);
    }

    ASSERT_EQ(s1.size()+s2.size(), concat.size());
}

/* Substr tests */
TEST(unitTestSecureString, CanGetSubStrOfStr)
{
    std::string s1("Hey Asshole!");
    std::string s2("Suck A Bag of Dicks!");
    secStr Str("Hey Asshole! Suck A Bag of Dicks!");

    ASSERT_EQ(Str.size(), 33u);
    secStr sent1 = Str.substr(0, 12);
    secStr sent2 = Str.substr(13, 20);

    ASSERT_EQ(sent1.size(), 12u);
    ASSERT_EQ(sent2.size(), 20u);

    for (size_t s=0; s<sent1.size(); ++s)
    {
        ASSERT_EQ(s1[s], (char)sent1[s]);
    }

    for (size_t s=0; s<sent2.size(); ++s)
    {
        ASSERT_EQ(s2[s], (char)sent2[s]);
    }
}

TEST(unitTestSecureString, SubStrBadLenThrowsOOR)
{
    secStr str("A short string");

    ASSERT_THROW(str.substr(0, 15), std::out_of_range);
}

TEST(unitTestSecureString, SubStrBadOffsetThrowsOOR)
{
    secStr str("short");

    ASSERT_THROW(str.substr(6, 5), std::out_of_range);
}

TEST(unitTestSecureString, EmptyStringHasSizeOfZero)
{
    secStr zed;

    ASSERT_EQ(zed.size(), 0ULL);
}

TEST(unitTestSecureString, NonEmptyStringRetsCorrectSize)
{
    secStr the_eighties("Shout, shout, let it all out");

    ASSERT_EQ(the_eighties.size(), 28ULL);
}

TEST(unitTestSecureString, SplitSplitsOnWhiteSpace)
{
    secStr space_sep_words("Shout Shout Let It All Out");
    auto split = space_sep_words.split(' ');

    ASSERT_EQ(split.size(), 6ULL);
    //These assume compare is working correctly
    ASSERT_EQ(split[0].compare("Shout"), 0);
    ASSERT_EQ(split[1].compare("Shout"), 0);
    ASSERT_EQ(split[2].compare("Let"), 0);
    ASSERT_EQ(split[3].compare("It"), 0);
    ASSERT_EQ(split[4].compare("All"), 0);
    ASSERT_EQ(split[5].compare("Out"), 0);
}

TEST(unitTestSecureString, EmptyOutStreamOPEmpty)
{
    secStr s;
    std::stringstream ss;

    ss << s;
    std::string S = ss.str();
    ASSERT_EQ(S.size(), 0u);
    ASSERT_EQ(S.compare(std::string("")), 0);
}

TEST(unitTestSecureString, OutStreamOP)
{
    secStr s("cedar meddling");
    std::string expected("cedar meddling");

    std::stringstream ss;
    ss << s;
    std::string actual = ss.str();

    ASSERT_EQ(actual.size(), 14u);
    ASSERT_EQ(expected.compare(actual), 0);
}

/* Test that the secure string dtor zero fills string on deletion */
TEST(unitTestSecureString, DestructorClearsStringData)
{
    std::string msg = "Super secret message that I don't want to be in memory after this object goes out of scope";
    secStr* tstMsg = new secStr(msg);
    const size_t sz = tstMsg->size(); //get the length of the string

    //This will be a deliberate dangling reference
    const uint8_t* content = tstMsg->byteStr();
    //delete the secStr calling its destructor that should zero out all the data in the string
    delete tstMsg;

    unique_ptr<uint8_t[]> null_cmp(new uint8_t[sz]());
    ASSERT_TRUE(memcmp(content, null_cmp.get(), sizeof(uint8_t)) == 0);
}
