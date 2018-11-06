#include "include/credCryptImpl.hpp"

credCryptImpl::credCryptImpl() : clean_(true), timeout_(30), timer_(timeout_)
{
    timer_.registerKey(&master_key_);
    timer_.start();
}

credCryptImpl::~credCryptImpl()
{
}

bool credCryptImpl::clearCredentials()
{
    auto nodes = reg_.traverse();

    for (auto &it : nodes)
    {
        reg_.erase(it->getIdentifier());
    }

    return reg_.size() == 0;
}

//The current valid rule is that a credential must have at least an account name, username and password
bool credCryptImpl::credentialIsValid(const Credential& cred) const
{
    return (cred.account.size() > 0 && cred.user_name.size() > 0 && cred.password.size() > 0);
}

bool credCryptImpl::deleteCredential(secStr& acnt)
{
    bool success = false;

    size_t start_size = reg_.size();

    if (start_size > 0)
    {
        reg_.deleteByHash(acnt);
        if (reg_.size() == (start_size-1)) { success = true; }
    }

    return success;
}

bool credCryptImpl::insertCredential(Credential& cred)
{
    timer_.reset();
    bool success = false;

    if (cred.account.size() > 0 && master_key_.isValid())
    {
        credential* cred_obj = nullptr;

        //all cred parameters filled
        if (cred.description.size() > 0 && cred.user_name.size() > 0 &&
            cred.password.size() > 0)
        {
            cred_obj = new credential(cred.account, cred.description,
                                      cred.user_name, cred.password,
                                      &master_key_);
        }
        //description not provided but all other parameters filled
        else if(cred.description.size() == 0 && cred.user_name.size() > 0 &&
                cred.password.size() > 0)
        {
            cred_obj = new credential(cred.account, cred.user_name,
                                      cred.password, &master_key_);
        }

        //Need a better check to ensure credential got inserted into tree not just created
        if (cred_obj != nullptr)
        {
            reg_.insert(make_unique<credential>(cred_obj));
            clean_ = false;
            success = true;
        }
    }

    return success;
}

bool credCryptImpl::getCredentials(vector<credential_data>& creds, const bool pw)
{
    timer_.reset();
    bool success = false;
    auto nodes = reg_.traverse();

    if (nodes.size() == reg_.size())
    {
        for (auto &cred : nodes)
        {
            //populate an external credential and fill the fields
            credential_data data{};

            data.account = cred->getAccountStr();
            data.description = cred->getDescriptionStr();
            data.user_name = cred->getUsernameStr();
            if (pw) { data.password = cred->getPasswordStr(); }

            creds.push_back(data);

            success = true;
        }

        //returning an empty vector for an empty tree is considered success
        if (reg_.size() == 0) { success = true; }
    }

    return success;
}

bool credCryptImpl::getCredential(secStr& acnt, credential_data& cred, const bool pw)
{
    timer_.reset();
    bool success = false;
    auto node = reg_.search(acnt);

    //We can only fill the credential structure if we have a valid master key
    if (node != nullptr && master_key_.isValid())
    {
        cred.account = node->getAccountStr();
        cred.description = node->getDescriptionStr();
        cred.user_name = node->getUsernameStr();
        //only populate pw if it was asked for
        if (pw) { cred.password = node->getPasswordStr(); }

        if (cred.account.size() > 0) { success = true; }
    }

    return success;
}

bool credCryptImpl::getPassword(secStr& acnt, secStr& pw)
{
    timer_.reset();
    bool success = false;
    credential* cred = nullptr;
    redBlackTreeNode* node = tree_.searchByHash(acnt);

    if (node != nullptr && node->value() != nullptr && master_key_.isValid())
    {
        cred = (credential*)node->value();
        pw = cred->getPasswordStr();
        success = true;
    }

    return success;
}

//TODO add a way to communicate non fatal load errors to the user
bool credCryptImpl::loadCredentialsFromFile(secStr& f_name, secStr& pw)
{
    timer_.stop();
    bool success = false;

    ifstream ifs((char*)f_name.byteStr(), ios_base::in|ios_base::binary);

    if (ifs.is_open())
    {
        headerReader HR(&master_key_);
        parser P(&master_key_);

        //reset the key
        master_key_.clearSalt();
        master_key_.clearKey();
        clean_ = true;

        if (HR.read(ifs))
        {
            ocbCtx ctx;

            //check the header and set, input the key into the key checker and attempt to decrypt if it is valid
            if (HR.headerIsValid(pw) &&
                checker_.hashKey((uint64_t*)master_key_.keyBytes(), KEY_WORD_SIZE) &&
                ocbSetup(&ctx,
                         (uint64_t*)master_key_.keyBytes(),
                         (uint64_t*)master_key_.saltBytes()))
            {
                timer_.reset(); //headerIsValid sets the masterKey on success
                //read then buffer the credential data
                const uint64_t data_size = HR.getCredsSize();
                unique_ptr<uint8_t[]> enc_data(new uint8_t[data_size]());
                ifs.read((char*)enc_data.get(), data_size); //read the encrypted credential
                secStr cred_data((uint8_t*)enc_data.get(), data_size);
                clearBuff(enc_data.get(), data_size);

                //authenticate and decrypt the data
                if (ocbDecrypt(&ctx,
                               cred_data.byteStr(),
                               cred_data.byteStr(),
                               cred_data.size()))
                { //decrypt the credentials then try to parse them
                    cred_data >> P;
                    P.parse();
                }
                else
                {
                    cerr << "Authentication failure decrypting credential file either file has been modified or corrupted" << endl;
                }
            }
            else
            {
                cerr << "Password is incorrect or the file loaded is not a valid CredCrypt file"
                     << endl;
            }
        }

        if (P.errorsOccured())
        {
            auto errors = P.getErrors();

            for (auto &it : errors)
            {
                cerr << "ERROR: " << it << endl;
            }
        }
        //insert the parsed credentials into the tree
        if (P.numCredentialsParsed() > 0)
        {
            auto to_load = P.getParsedCredentials();
            for (auto &it: to_load)
            {
                size_t start_size = reg_.size();
                auto node = FINISH ME
                redBlackTreeNode* node = new redBlackTreeNode(it);
                reg_.insertNode(node);
                if (reg_.size() != (start_size + 1)) //sanity check
                {
                    cerr << "ERROR: inserting credential into tree" << endl;
                    delete node;
                    node = nullptr;
                }
            }

            //keep the salt we just loaded from getting cleared on the next pw enter
            clean_ = false;
            timer_.reset();

            if (tree_.size() > 0) { clean_ = false; }
            if (P.numCredentialsParsed() == tree_.size()) { success = true; }
        }
        ifs.close();
    }

    return success;
}

bool credCryptImpl::saveCredentialsToFile(secStr& f_name)
{
    timer_.reset();
    bool success = false;
    headerWriter HW(&master_key_);
    auto creds = tree_.listNodes();

    if (creds.size() > 0 && master_key_.isValid() && HW.isValid())
    {
        ocbCtx ctx;
        stringstream ss;
        /* save to a temp file then rename on success to prevent failure during writing
         * from corrupting existing credential files */
        secStr temp_ext(".tmp");
        secStr temp_file = f_name + temp_ext;

        ofstream ofs((char*)temp_file.byteStr(), ios_base::out|ios_base::binary);
        if (ofs.good())
        {
            //generate the json
            ss << "{";
            for (size_t s=0; s<creds.size(); ++s)
            {
                ss << "\"credential" << s+1 << "\":" << (credential*)creds[s]->value();
                if (s != (creds.size()-1)) { ss << ","; }
            }
            ss << "}";

            //buffer the json
            secStr json(ss.str());
            unique_ptr<uint8_t[]> data(new uint8_t[json.size()+OCB_TAG_BYTE_SIZE]());
            memcpy(data.get(), json.byteStr(), json.size());

            //setup OCB mode
            if (ocbSetup(&ctx,
                         (uint64_t*)master_key_.keyBytes(),
                         (uint64_t*)master_key_.saltBytes()))
            {
                //tell the header writer how big the encrypted content to follow is
                HW.setCredSize(json.size()+OCB_TAG_BYTE_SIZE);
                if (HW.write(ofs)) //write the header
                {
                    //encrypt the data and write it to the file
                    ocbEncrypt(&ctx, data.get(), data.get(), json.size());
                    ofs.write((char*)data.get(), json.size()+OCB_TAG_BYTE_SIZE);
                    success = true;
                }
            }
            clearBuff(data.get(), json.size()+OCB_TAG_BYTE_SIZE);
        }
        ofs.close();
        //rename the file to f_name on write success
        if (success)
        {
            success = (rename((char*)temp_file.byteStr(), (char*)f_name.byteStr())) == 0 ?
                true : false;
        }
    }

    return success;
}

/* this will be faster then inserting a new credential over the top of an existing one in cases
 * where we are only updating one or two fields
 */
bool credCryptImpl::updateCredential(Credential& cred)
{
    timer_.reset();
    bool success = false;

    //only continue if the credential exists
    if (cred.account.size() > 0 &&
       (cred.user_name.size() > 0 ||
        cred.description.size() > 0 ||
        cred.password.size() > 0))
    {
        auto node = tree_.searchByHash(cred.account);
        credential* cred_to_update = (credential*)node->value();
        if (node != nullptr && cred_to_update != nullptr)
        {
            bool op_success = true;
            /* update any non empty string fields in the Credential
            * If any update operation reports failure then stop any other updates and report
            * the failure
            */
            if (cred.description.size() > 0 && op_success)
            {
                op_success = cred_to_update->updateDescription(cred.description);
            }
            if (cred.password.size() > 0 && op_success)
            {
                op_success = cred_to_update->updatePassword(cred.password);
            }
            if (cred.user_name.size() > 0 && op_success)
            {
                op_success = cred_to_update->updateUsername(cred.user_name);
            }

            if (op_success) { success = true; }
        }
    }

    return success;
}
