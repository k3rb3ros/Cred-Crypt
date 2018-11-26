#pragma once

#include "secureString.hpp"

/*
 *  This struct a logical grouping of all human readable data stored in a credential
 *  in unencrypted form. It is used when getting data out of or putting data in a credential.
 *  Several raw functions have also been provided to verfy if a credential is correct
 */
struct credentialData
{
    secStr account_{};
    secStr description_{};
    secStr username_{};
    secStr password_{};

    static bool isValid(const credentialData& cred)
    {
        return
            (cred.account_.size() > 0
             && cred.username_.size() > 0
             && cred.password_.size() > 0
            );
    }
};
