#include <iostream> //cout, endl
#include <sstream> //stringstream class
#include <string> //std::string class
#include "include/api.hpp" //CredCrypt api
#include "include/credentialData.hpp" //credentialData class
#include "include/secureString.hpp" //secStr class

using std::cout;
using std::endl;
using std::stringstream;
using std::vector;

inline void printCE(credCrypt& inst, secStr& acnt)
{
    if (inst.credentialExists(acnt))
    {
        cout << "credential(" << acnt << ")" << " exists" << endl;
    }
    else
    {
        cout << "credential(" << acnt << ")" << " does NOT exist" << endl;
    }
}

inline void printcredential(credentialData& cred, secStr name)
{
    cout << "credential(" << name << ") { account:\"" << cred.account_ << "\" description:\""
         << cred.description_ << "\" username:\"" << cred.username_ << "\" password:\""
         << cred.password_ << "\" }" << endl;
}

inline void printAllcredentials(vector<credentialData>& creds)
{
    if (creds.size() == 0)
    {
        cout << "No credentials in manager" << endl;
    }

    else
    {
        for (size_t s=0; s<creds.size(); ++s)
        {
            stringstream ss;
            ss << (s+1);
            printcredential(creds[s], secStr(ss.str()));
        }
    }
}

int main()
{
    credCrypt instance;
    credentialData dummy_cred;
    secStr out_f(".cc.crd");

    dummy_cred.account_ = secStr("account");
    dummy_cred.description_ = secStr("description");
    dummy_cred.username_ = secStr("username");
    dummy_cred.password_ = secStr("password");

    secStr pw("R3411y1337P455W0RD");
    cout << "Creating master key" << endl;
    instance.inputPassword(pw);
    cout << "Inserting credential \"account\"" << endl;
    instance.insertCredential(dummy_cred);
    printCE(instance, dummy_cred.account_);
    cout << "Searching for credential \"account\"" << endl;
    credentialData cred1NoPW = instance.viewFullCredential(dummy_cred.account_);
    printcredential(cred1NoPW, secStr("cred1NoPW"));
    credentialData cred1PW = instance.viewFullCredential(dummy_cred.account_, true);
    printcredential(cred1PW, secStr("cred1PW"));
    cout << "Deleting credential \"account\"" << endl;
    instance.deleteCredential(dummy_cred.account_);
    printCE(instance, dummy_cred.account_);

    credentialData farce_book;
    farce_book.account_ = secStr("Farcebook");
    farce_book.username_ = secStr(" ");
    farce_book.password_ = secStr("IAmDumb!");
    instance.insertCredential(farce_book);
    printCE(instance, farce_book.account_);
    farce_book.description_ = secStr("My source of news");
    farce_book.username_ = secStr("JimBob");
    farce_book.password_ = secStr("Trump1234");
    instance.updateCredential(farce_book);
    credentialData fb_upd = instance.viewFullCredential(farce_book.account_);
    printcredential(fb_upd, secStr("Farcebook"));
    cout << "viewPassword() " << instance.viewPassword(fb_upd.account_)<< endl;

    instance.insertCredential(dummy_cred);
    vector<credentialData> all_creds;
    instance.listAllCredentials(all_creds);
    printAllcredentials(all_creds);
    all_creds.clear();
    instance.listAllCredentials(all_creds, true);
    printAllcredentials(all_creds);

    cout << "Saving credentials to file " << out_f << endl;
    instance.saveCredentialsToFile(out_f);

    cout << "Clearing all credentials" << endl;
    instance.clearCredentials();
    all_creds.clear();
    instance.inputPassword(pw);
    instance.listAllCredentials(all_creds);
    printAllcredentials(all_creds);

    cout << "Loading credentials from file " << out_f << endl;
    instance.loadCredentialsFromFile(out_f, pw);

    return 0;
}
