#include "include/api.hpp"

//TODO revaulate throwing invalid key exceptions when password times out or has not been inputed

bool credCrypt::credentialExists(secStr& acnt)
{
    return impl_.credentialExists(acnt);
}

bool credCrypt::inputPassword(secStr& pw)
{
    return impl_.inputPassword(pw);
}

bool credCrypt::keyIsValid()
{
    return (impl_.master_key_.isValid() &&
            impl_.checker_.checkKey((uint64_t*)impl_.master_key_.keyBytes(), KEY_WORD_SIZE));
}

credentialData credCrypt::viewFullCredential(secStr& acnt, bool pw)
{
    credentialData cred{};
    if (!impl_.master_key_.isValid()) { throw InvalidKeyException(); }

    if (!impl_.getCredential(acnt, cred, pw)) { throw InvalidCredentialException(); }

    return cred;
}

secStr credCrypt::viewPassword(secStr& acnt)
{
    if (!impl_.master_key_.isValid()) { throw InvalidKeyException(); }
    secStr password;

    if (acnt.size() > 0 && impl_.reg_.search(identifier{acnt}))
    {
        if (!impl_.getPassword(acnt, password)) { throw InvalidCredentialException(); }
    }
    else { throw CredentialNotFoundException(); }

    return password;
}

void credCrypt::clearCredentials()
{
    impl_.master_key_.clearKey();
    impl_.master_key_.clearSalt();

    if (impl_.clearCredentials()) { impl_.clean_ = true; }
    else { throw CredentialClearException(); }
}

void credCrypt::deleteCredential(secStr& acnt)
{
    if (!impl_.deleteCredential(acnt)) { throw CredentialNotFoundException(); }
}

void credCrypt::insertCredential(credentialData& cred)
{
    if (!impl_.master_key_.isValid()) { throw InvalidKeyException(); }

    if (impl_.credentialIsValid(cred)) { impl_.insertCredential(cred); }
    else { throw InvalidCredentialException(); }
}

void credCrypt::listAllCredentials(std::vector<credentialData>& creds, bool pw)
{
    if (!impl_.master_key_.isValid()) { throw InvalidKeyException(); }
    if (!impl_.getCredentials(creds, pw)) { throw InvalidCredentialException(); }
}

void credCrypt::loadCredentialsFromFile(secStr& f_name, secStr& pw)
{
    if (impl_.reg_.size() > 0) { throw DestructiveOperationException(); }
    if (!impl_.loadCredentialsFromFile(f_name, pw)) { throw CredentialLoadException(); }
}

void credCrypt::updateCredential(credentialData &cred)
{
    if (!impl_.master_key_.isValid()) { throw InvalidKeyException(); }
    if (impl_.reg_.search(identifier{cred.account_}) != nullptr)
    {
        if (!impl_.updateCredential(cred))
        {
            throw InvalidCredentialException();
        }
    }
    else { throw CredentialNotFoundException(); }
}

//void credCrypt::saveCredentialsToFile(secStr& f_name)
void credCrypt::saveCredentialsToFile(secStr& f_name)
{
    if (!impl_.saveCredentialsToFile(f_name)) { throw CredentialSaveException(); }
}
