#include <iostream> //cout, endl
#include <sstream> //stringstream class
#include <string> //std::string class
#include "include/api.hpp" //CredCrypt api
#include "include/secureString.hpp" //secStr class

using std::cout;
using std::endl;
using std::stringstream;
using std::vector;

inline void printCE(credCrypt& inst, secStr& acnt)
{
    if (inst.credentialExists(acnt))
    {
        cout << "Credential(" << acnt << ")" << " exists" << endl;
    }
    else
    {
        cout << "Credential(" << acnt << ")" << " does NOT exist" << endl;
    }
}

inline void printCredential(Credential& cred, secStr name)
{
    cout << "Credential(" << name << ") { account:\"" << cred.account << "\" description:\""
         << cred.description << "\" username:\"" << cred.user_name << "\" password:\""
         << cred.password << "\" }" << endl;
}

inline void printAllCredentials(vector<Credential>& creds)
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
            printCredential(creds[s], secStr(ss.str()));
        }
    }
}

int main()
{
    credCrypt instance;
    Credential dummy_cred;
    secStr out_f(".cc.crd");

    dummy_cred.account = secStr("account");
    dummy_cred.description = secStr("description");
    dummy_cred.user_name = secStr("username");
    dummy_cred.password = secStr("password");

    secStr pw("R3411y1337P455W0RD");
    cout << "Creating master key" << endl;
    instance.inputPassword(pw);
    cout << "Inserting credential \"account\"" << endl;
    instance.insertCredential(dummy_cred);
    printCE(instance, dummy_cred.account);
    cout << "Searching for credential \"account\"" << endl;
    Credential cred1NoPW = instance.viewFullCredential(dummy_cred.account);
    printCredential(cred1NoPW, secStr("cred1NoPW"));
    Credential cred1PW = instance.viewFullCredential(dummy_cred.account, true);
    printCredential(cred1PW, secStr("cred1PW"));
    cout << "Deleting credential \"account\"" << endl;
    instance.deleteCredential(dummy_cred.account);
    printCE(instance, dummy_cred.account);

    Credential farce_book;
    farce_book.account = secStr("Farcebook");
    farce_book.user_name = secStr(" ");
    farce_book.password = secStr("IAmDumb!");
    instance.insertCredential(farce_book);
    printCE(instance, farce_book.account);
    farce_book.description = secStr("My source of news");
    farce_book.user_name = secStr("JimBob");
    farce_book.password = secStr("Trump1234");
    instance.updateCredential(farce_book);
    Credential fb_upd = instance.viewFullCredential(farce_book.account);
    printCredential(fb_upd, secStr("Farcebook"));
    cout << "viewPassword() " << instance.viewPassword(fb_upd.account)<< endl;

    instance.insertCredential(dummy_cred);
    vector<Credential> all_creds;
    instance.listAllCredentials(all_creds);
    printAllCredentials(all_creds);
    all_creds.clear();
    instance.listAllCredentials(all_creds, true);
    printAllCredentials(all_creds);

    cout << "Saving credentials to file " << out_f << endl;
    instance.saveCredentialsToFile(out_f);

    cout << "Clearing all credentials" << endl;
    instance.clearCredentials();
    all_creds.clear();
    instance.inputPassword(pw);
    instance.listAllCredentials(all_creds);
    printAllCredentials(all_creds);

    cout << "Loading credentials from file " << out_f << endl;
    instance.loadCredentialsFromFile(out_f, pw);

    return 0;
}
