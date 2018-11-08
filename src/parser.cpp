#include "include/parser.hpp"

parser::parser(const masterKey& mk, vector<unique_ptr<credential>>& cred_container):
   mk_{mk}, creds_{cred_container}
{}

parser::~parser()
{
    if (input_.get() != nullptr &&
        strlen(input_.get()) > 0)
    {
        clearBuff((uint8_t*)input_.get(), strlen(input_.get()));
    }
    if (output_ != nullptr) { cJSON_Delete(output_); output_ = nullptr; }
}

bool parser::errorsOccured() { return errors_.size() > 0; }

vector<secStr> parser::getErrors() { return errors_; }

size_t parser::numCredentialsParsed() { return creds_.size(); }

void parser::clear()
{
    if (strlen(input_.get()) > 0)
    { clearBuff((uint8_t*)input_.get(), strlen(input_.get())); }
    input_ = unique_ptr<char[]>(nullptr);

    if (output_ != nullptr) { cJSON_Delete(output_); output_ = nullptr; }
    creds_.clear();
    errors_.clear();
}

void parser::parse()
{
    if (input_ != nullptr)
    {
        #ifdef DBG_PARSER
        cout << input_ << endl;
        #endif
        output_ = cJSON_Parse(input_.get());
        if (output_ != nullptr)
        {
            parseInternal();
        }
        else
        {
            auto parse_error = secStr("Error parsing JSON");
            errors_.push_back(parse_error);
        }
    }
    else
    {
        auto no_input = secStr("No input to parse");
        errors_.push_back(no_input);
    }
}

istream& operator>>(istream& in, parser& rhs)
{
    if (in)
    {
        size_t in_start = in.tellg();
        in.seekg(0, ios_base::end);
        size_t in_end = in.tellg();
        in.seekg(in_start);

        rhs.input_ = unique_ptr<char[]>(new char[(in_end-in_start) + 1]());

        in.readsome(rhs.input_.get(), (in_end-in_start));
    }

    return in;
}

secStr& operator>>(secStr& lhs, parser& rhs)
{
    if (lhs.size() > 0)
    {
        rhs.input_ = unique_ptr<char[]>(new char[lhs.size() + 1]());
        for (size_t s=0; s<lhs.size(); ++s)
        {
            rhs.input_[s] = lhs[s];
        }
    }

    return lhs;
}

inline bool parser::isCredential(cJSON* obj)
{
    bool is_cred = false;

    if (obj != nullptr)
    {
        cJSON* obj_type = cJSON_GetObjectItem(obj, "object");
        if (obj_type != nullptr && strncmp(obj_type->valuestring, "credential", 10) == 0)
        {
            cJSON* acnt = cJSON_GetObjectItem(obj, "account");
            cJSON* uname = cJSON_GetObjectItem(obj, "username");
            cJSON* pw = cJSON_GetObjectItem(obj, "password");
            cJSON* id = cJSON_GetObjectItem(obj, "id");
            cJSON* hash = cJSON_GetObjectItem(obj, "hash");
            cJSON* salt = cJSON_GetObjectItem(obj, "salt");

            if (acnt != nullptr && uname != nullptr &&
                pw != nullptr && id != nullptr &&
                hash != nullptr && salt != nullptr)
            {
                is_cred = true;
            }
        }
    }

    return is_cred;
}

inline void parser::parseInternal()
{
    if (output_ != nullptr)
    {
        cJSON* j_obj = output_->child;
        while (j_obj != nullptr) //parse each subobject
        {
            //check what type of object it is
            if (isCredential(j_obj))
            {
                cJSON* acnt = cJSON_GetObjectItem(j_obj, "account");
                cJSON* desc = cJSON_GetObjectItem(j_obj, "description");
                cJSON* uname = cJSON_GetObjectItem(j_obj, "username");
                cJSON* pw = cJSON_GetObjectItem(j_obj, "password");
                cJSON* id = cJSON_GetObjectItem(j_obj, "id");
                cJSON* hash = cJSON_GetObjectItem(j_obj, "hash");
                cJSON* salt = cJSON_GetObjectItem(j_obj, "salt");

                secStr acnt_hex(acnt->valuestring);
                secStr desc_hex(desc->valuestring);
                secStr uname_hex(uname->valuestring);
                secStr pw_hex(pw->valuestring);
                secStr id_hex(id->valuestring);
                secStr hash_hex(hash->valuestring);
                secStr salt_hex(salt->valuestring);

                //instantiate the credential
                auto cred =
                    make_unique<credential>
                    (acnt_hex,
                     desc_hex,
                     uname_hex,
                     pw_hex,
                     id_hex,
                     hash_hex,
                     salt_hex,
                     mk_
                    );

                if (cred->isValid())
                {
                    creds_.push_back(move(cred));
                }
                else
                { //delete the credential and report the error
                    auto cred_err = secStr("A credential failed its hash check and was not loaded");
                    errors_.push_back(cred_err);
                }
            }
            j_obj = j_obj->next;
        }
    }
}
