#include "include/cli.hpp"

//used to consistently change actions
static inline void change_action(cred_crypt_state &state, action new_action,
                                 bool collect_inp=true, bool save_prev=true)
{
    if (save_prev) { state.prev_action_ = state.action_; }
    state.action_ = new_action;
    state.collect_input_ = collect_inp;
}

static inline void get_input(cred_crypt_state &state)
{
    if (state.collect_input_)
    {
        secStr line;
        getline(cin, line, '\n');
        if (!cin.good())
        {
            state.running_ = false;
        }
        else
        {
            auto input = line.splitWQuotes(' '); //split the line on whitespace
            state.input_ = input;
        }
    }
}

static inline void print_credential(Credential& cred)
{
    cout << "{ " << endl
         << "\t" << "account: " << cred.account << endl;
    if (cred.description.size() > 0)
    {
        cout << "\t" << "description: " << cred.description << endl;
    }
    cout << "\t" << "username: " << cred.user_name << endl;
    if (cred.password.size() > 0)
    {
        cout << "\t" << "password: " << cred.password << endl;
    }
    cout << "}" << endl;
}

static inline void print_credentials(vector<Credential> &creds)
{
    if (creds.size() > 0)
    {
        for (auto &it : creds)
        {
            print_credential(it);
        }
    }
    else { cout << "None" << endl; }
}

static inline void print_op_status(bool success)
{
    if (success) { cout << "Success" << endl; }
    else { cerr << "Failure" << endl; }
}

static inline secStr get_password()
{
    bool echo = true;
    secStr pw;
    struct termios old_t, new_t;

    if (tcgetattr(STDIN_FILENO, &old_t) == 0)
    {
        new_t = old_t;
        new_t.c_lflag &= ~ECHO;

        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_t) == 0)
        {
            echo = false;
            getline(cin, pw, '\n');
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_t);
        }
    }

    if (echo) { cerr << "Error disabling Terminal echo" << endl; }

    return pw;
}

static inline void execute_action(cred_crypt_state &state)
{
    bool success = true;
    secStr pw;

    //take the action determined by the parser
    switch (state.action_)
    {
        case ABRT:
            cout << "Action aborted" << endl;
        break;
        case CHK_CRED_EXST:
            //cout << "Check if credential exists" << endl;
            if (state.instance_->credentialExists(*(state.input_[1].get())))
            {
                cout << "Credential " << *state.input_[1].get() << " Exists" << endl;
            }
            else
            {
                cout << "Credential " << *state.input_[1].get() << " Does not exist" << endl;
            }
        break;
        case CHK_KEY_VALID:
            //cout << "Check if valid Key is loaded" << endl;
            if (state.instance_->keyIsValid())
            {
                cout << "Valid master key loaded" << endl;
            }
            else
            {
                cout << "Valid master key not loaded" << endl;
            }
        break;
        //this is a destructive action so we prompt the user to confirm before performing it
        case CLR_ALL_CREDS:
            //cout << "Clear credential" << endl;
            if (state.confirmed_)
            {
                cout << "Clearing all credentials... ";
                //clear all credentials
                success = true;
                try
                {
                    state.instance_->clearCredentials();
                }
                catch (const CredentialClearException e)
                {
                    success = false;
                    state.status_ = -1;
                    cerr << e.what() << " ";
                }

                print_op_status(success); //report the status of the operation
                //reset the confirmed flag
                state.confirmed_ = false;
            }
            else
            {   //ask the user for confirmation
                assert(!state.confirmed_);
                cout << "The action you have selected will destroy all unsaved credentials are you sure you want to continue? Type \"Yes!\" to confirm." << endl;
                change_action(state, CONFIRM, true);
            }
        break;
        case CONFIRM:
            state.confirmed_ = false;
            change_action(state, NO_ACTION);
        break;
        case DEL_CRED:
            cout << "Deleting credential " << *state.input_[1].get() << "... ";
            success = true;
            try
            {
                state.instance_->deleteCredential(*(state.input_[1].get()));
            }
            catch (const CredentialNotFoundException e)
            {
                success = false;
                state.status_ = -1;
                cerr << e.what() << endl;
            }
            print_op_status(success); //report the status of the operation
        break;
        case HELP:
            cout << help_msg << endl;
        break;
        case INPT_PW:
            if (!state.instance_->keyIsValid())
            {
                cout << enter_pw_msg << endl;
                auto pw = get_password();
                success = (state.instance_->inputPassword(pw) && state.instance_->keyIsValid());

                //perform the previous action if it switched to INPT_PW
                if (success && state.action_ != state.prev_action_ &&
                    state.prev_action_ != CLR_ALL_CREDS) //keeps creds from double clearing
                {
                    change_action(state, state.prev_action_, false);
                }
                else
                {
                    if (!success) { cerr << "Incorrect master password" << endl; }
                    change_action(state, NO_ACTION);
                }
            }
            else
            {
                cout << "Master key already loaded" << endl;
                change_action(state, NO_ACTION);
            }
        break;
        case INS_CRED:
            if (state.instance_->keyIsValid())
            {
                Credential cred;
                if (state.input_.size() == 4) //cred with no description
                {
                    cred.account = *state.input_[1].get();
                    cred.user_name = *state.input_[2].get();
                    cred.password = *state.input_[3].get();
                }
                else if (state.input_.size() == 5) //cred with description
                {
                    cred.account = *state.input_[1].get();
                    cred.description = *state.input_[2].get();
                    cred.user_name = *state.input_[3].get();
                    cred.password = *state.input_[4].get();
                }

                cout << "Inserting credential " << cred.account << "... ";
                try
                {
                    state.instance_->insertCredential(cred);
                }
                catch (const InvalidCredentialException e)
                {
                    success = false;
                    state.status_ = -1;
                    cerr << e.what() << endl;
                }
                print_op_status(success); //report the status of the operation
                change_action(state, NO_ACTION);
            }
            else
            {
                change_action(state, INPT_PW, false);
            }
        break;
        case LIST_ALL_CREDS:
            if (state.instance_->keyIsValid())
            {
                bool pw = false;
                vector<Credential> creds;

                if (state.input_.size() == 2 && (state.input_[1]->size() >= 4))
                {
                    secStr cmp = state.input_[1]->substr(0, 4);
                    if (cmp.compare(secStr("true")) == 0 ||
                        cmp.compare(secStr("True")) == 0)
                    {
                        pw = true;
                    }
                }

                try
                {
                    state.instance_->listAllCredentials(creds, pw);
                }
                catch (const InvalidCredentialException e)
                {
                    state.status_ = -1;
                    cerr << "One or more credentials retrieved were invalid" << endl;
                }

                change_action(state, NO_ACTION);

                cout << "Credentials currently stored in manager" << endl;
                print_credentials(creds);
            }
            else
            {
                change_action(state, INPT_PW, false);
            }
        break;
        case LOAD_CREDS:
            cout << enter_pw_msg << endl;
            pw = get_password();

            if (state.input_.size() == 1)
            {
                state.cred_file_ = dflt_cred_file;
            }
            else if (state.input_.size() == 2)
            {
                state.cred_file_ = *state.input_[1];
            }
            try
            {
                cout << "Loading credentials from file " << state.cred_file_ << "... ";
                state.instance_->loadCredentialsFromFile(state.cred_file_, pw);
            }
            catch (const DestructiveOperationException e)
            {
                success = false;
                cerr << "ERROR: Loading credentials from file would destroy currently loaded credentials, clear the manager before loading credentials from a file" << endl;
            }
            catch (const CredentialLoadException e)
            {
                success = false;
                cerr << e.what() << endl;
            }
            print_op_status(success);
            change_action(state, NO_ACTION);
        break;
        case PRSE_ERR:
            cout << "Unrecognized or invalid command" << endl;
        break;
        case QUIT:
            cout << "Quiting... " << endl;
            state.running_ = false;
        break;
        case SAVE_CREDS:
            if (state.instance_->keyIsValid())
            {
                if (!state.confirmed_ && state.input_.size() == 1)
                {
                    state.cred_file_ = dflt_cred_file;
                }
                else if (!state.confirmed_ && state.input_.size() == 2)
                {
                    state.cred_file_ = *state.input_[1];
                }

                if (exists((char*)state.cred_file_.byteStr()) && !state.confirmed_)
                {
                    cout << state.cred_file_ << " already exists do you want to overwrite it? Type \"Yes!\" to confirm." << endl;
                    change_action(state, CONFIRM, true);
                }
                else //save the credentials to file
                {
                    try
                    {
                        cout << "Saving credentials to file " << state.cred_file_ << "... ";
                        state.instance_->saveCredentialsToFile(state.cred_file_);
                    }
                    catch (const CredentialSaveException e)
                    {
                        success = false;
                        cerr << e.what() << endl;
                    }
                    state.confirmed_ = false;
                    print_op_status(success);
                }
            }
            else
            {
                assert(!state.instance_->keyIsValid());
                change_action(state, INPT_PW, false);
            }
        break;
        case UPD_CRED:
            if (state.instance_->keyIsValid())
            {
                if (state.instance_->credentialExists(*state.input_[1]))
                {
                    shared_ptr<secStr> description = make_shared<secStr>(secStr());
                    shared_ptr<secStr> username = make_shared<secStr>(secStr());
                    shared_ptr<secStr> password = make_shared<secStr>(secStr());
                    for (size_t s=2; s<state.input_.size(); ++s)
                    {
                        auto parse = state.input_[s]->split(':');
                        if (parse.size() == 2)
                        {
                            if (parse[0]->compare("description") == 0)
                            {
                                description = parse[1];
                            }
                            else if (parse[0]->compare("username") == 0)
                            {
                                username = parse[1];
                            }
                            else if (parse[0]->compare("password") == 0)
                            {
                                password = parse[1];
                            }
                        }
                    }
                    Credential update;
                    update.account = *state.input_[1];
                    update.description = *description;
                    update.user_name = *username;
                    update.password = *password;
                    try
                    {
                        cout << "Updating credential " << *state.input_[1] << "... ";
                        state.instance_->updateCredential(update);
                    }
                    catch (const InvalidCredentialException e)
                    {
                        success = false;
                        cerr << e.what() << endl;
                    }
                    print_op_status(success);
                }
            }
            else
            {
                assert(!state.instance_->keyIsValid());
                change_action(state, INPT_PW, false);
            }
        break;
        case VIEW_CRED:
            if (state.instance_->keyIsValid())
            {
                bool pw = false;
                if (state.input_.size() >= 2 &&
                    state.input_.size() <= 3 &&
                    state.input_[1]->size() >= 4)
                {
                    if (state.input_.size() == 3 && state.input_[2]->size() >= 4)
                    {
                        secStr cmp = state.input_[2]->substr(0, 4);
                        if (cmp.compare(secStr("true")) == 0 ||
                            cmp.compare(secStr("True")) == 0)
                        {
                            pw = true;
                        }
                    }
                }

                try
                {
                    Credential cred = state.instance_->viewFullCredential(*state.input_[1], pw);
                    print_credential(cred);
                }
                catch (const InvalidCredentialException e)
                {
                    success = false;
                    cerr << e.what() << endl;
                }
            }
            else
            {
                assert(!state.instance_->keyIsValid());
                change_action(state, INPT_PW, false);
            }
        break;
        case VIEW_PW:
            if (state.instance_->keyIsValid())
            {
                if (state.instance_->credentialExists(*state.input_[1]))
                {
                    try
                    {
                        secStr cred_pw = state.instance_->viewPassword(*state.input_[1]);
                        cout << "Credential " << *state.input_[1] << " { password: " << cred_pw
                             << " }" << endl;
                    }
                    catch (const InvalidCredentialException e)
                    {
                        cerr << e.what() << endl;
                    }
                }
                else
                {
                    cout << "Credential " << *state.input_[1] << " does not exist" << endl;
                }
            }
            else
            {
                assert(!state.instance_->keyIsValid());
                change_action(state, INPT_PW, false);
            }
        break;
        case NO_ACTION:
        default:
        break;
    }
    cout << endl;
}

static inline void parse_input(cred_crypt_state &state)
{
    if (state.input_.size() > 0 && state.input_[0]->size() >=4)
    {
        secStr cmd = state.input_[0]->substr(0, 4);
        if (state.action_ != CONFIRM && state.input_.size() > 0)
        { 
            if ((cmd.compare(secStr("exis")) == 0 || cmd.compare(secStr("Exis")) == 0) &&
                 state.input_.size() == 2)
            {
                change_action(state, CHK_CRED_EXST);
            }
            else if ((cmd.compare(secStr("clea")) == 0 || cmd.compare(secStr("Clea")) == 0) &&
                      state.input_.size() == 1) //clearCredentials()
            {
                change_action(state, CLR_ALL_CREDS);
            }
            else if ((cmd.compare(secStr("dele")) == 0 || cmd.compare(secStr("Dele")) == 0) &&
                      state.input_.size() <= 2) //deleteCredential(acnt)
            {
                change_action(state, DEL_CRED);
            }
            else if ((cmd.compare(secStr("inse")) == 0 || cmd.compare(secStr("Inse")) == 0) &&
                     (state.input_.size() == 4 || state.input_.size() == 5))
                //insertCredential(cred) { acnt, (opt)desc, uname, pw }
            {
                change_action(state, INS_CRED);
            }
            else if (cmd.compare(secStr("help")) == 0 || cmd.compare(secStr("Help")) == 0)
            {
                change_action(state, HELP);
            }
            else if ((cmd.compare(secStr("list")) == 0 || cmd.compare(secStr("Load")) == 0) &&
                      state.input_.size() <= 2) //listAllCredentials(creds, (opt)pw)
            {
                change_action(state, LIST_ALL_CREDS);
            }
            else if ((cmd.compare(secStr("load")) == 0 || cmd.compare(secStr("Load")) == 0) &&
                     (state.input_.size() == 1 || state.input_.size() == 2))
                //loadCredential(fname, pw) pw will be asked for later
            {
                change_action(state, LOAD_CREDS);
            }
            else if ((cmd.compare(secStr("look")) == 0 || cmd.compare(secStr("Look")) == 0) &&
                      state.input_.size() == 2) //viewPassword(acnt)
            {
                change_action(state, VIEW_PW);
            }
            else if ((cmd.compare(secStr("pass")) == 0 || cmd.compare(secStr("Pass")) == 0) &&
                      state.input_.size() == 1) //inputPassword(pw)
            {
                change_action(state, INPT_PW);
            }
            else if ((cmd.compare(secStr("quit")) == 0 || cmd.compare(secStr("Quit")) == 0) &&
                      state.input_.size() == 1) //quit()
            {
                change_action(state, QUIT);
            }
            else if ((cmd.compare(secStr("save")) == 0 || cmd.compare(secStr("Save")) == 0) &&
                     (state.input_.size() == 1 || state.input_.size() == 2))
                //saveCredentialsToFile(f_name) (if f_name is missing use default
            {
                state.action_ = SAVE_CREDS;
            }
            else if ((cmd.compare(secStr("upda")) == 0 || cmd.compare(secStr("Upda")) == 0) &&
                    (state.input_.size() >= 3 && state.input_.size() <= 5))
                //updateCredential(cred) { accout, (opt)desc, (opt)uname, (opt)pw }
            {
                change_action(state, UPD_CRED);
            }
            else if ((cmd.compare(secStr("vali")) == 0 || cmd.compare(secStr("Vali")) == 0) &&
                      state.input_.size() == 1) //keyIsValid()
            {
                change_action(state, CHK_KEY_VALID);
            }
            else if ((cmd.compare(secStr("view")) == 0 || cmd.compare(secStr("View")) == 0) &&
                      (state.input_.size() == 2 || state.input_.size() == 3))
                //viewFullCredential(acnt, pw) pw is optional assumed to be false if not provided
            {
                change_action(state, VIEW_CRED);
            }
            /*
            else if (state.input_.size() == 1)
            {
            }
            else if ()
            {
            }
            */
            else if (state.input_.size() == 0)
            {
                change_action(state, PRSE_ERR);
            }
        }
        else //confirm destructive action logic
        {
            assert(state.action_ == CONFIRM);
            if (cmd.compare(secStr("Yes!")) == 0)
            {
                state.confirmed_ = true;
                change_action(state, state.prev_action_, true, false);
            }
            else 
            {
                state.confirmed_ = false;
                change_action(state, ABRT);
            }
        }
    }
    else if (state.action_ == CONFIRM)
    {
        change_action(state, ABRT);
    }
    else if (state.input_.size() == 0)
    {
        change_action(state, NO_ACTION);
    }
    else
    {
        change_action(state, PRSE_ERR);
    }
}

int main()
{
    cred_crypt_state state;
    credCrypt instance;
    state.instance_ = &instance;
   
    cout << border << intro_msg << "#   " << VERSION_MAJOR << "." << VERSION_MINOR << "   #\r\n"
         << border << endl;

    //main event loop
    while (state.running_)
    {
        if (state.collect_input_)
        {
            get_input(state);
            parse_input(state);
        }
        else { state.collect_input_ = true; }
        execute_action(state);
        sleep_for(milliseconds(50));
    }

    return state.status_;
}
