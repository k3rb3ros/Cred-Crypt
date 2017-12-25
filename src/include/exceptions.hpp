#pragma once

#include <exception>
#include <string>

using std::exception;
using std::string;

class CredentialClearException : public exception
{
    public:

    const char* what() const noexcept
    {
        return "Error clearing all credentials";
    }
};

class CredentialNotFoundException : public exception
{
    public:

    const char* what() const noexcept
    {
        return "The credential could not be found";
    }
};

class CredentialLoadException : public exception
{
    public:

    const char* what() const noexcept
    {
        return "An error occured that prevented credentials from being loaded";
    }
};

class CredentialSaveException : public exception
{
    public:

    const char* what() const noexcept
    {
        return "An error occured that prevented credentials from being saved";
    }
};

class DestructiveOperationException : public exception
{
    public:

    const char* what() const noexcept
    {
        return "An operation was requested that would destroy key information for one or more currently loaded credentials";
    }
};

class InvalidCredentialException : public exception
{
    public:

    const char* what() const noexcept
    {
        return "Invalid credential specified";
    }
};

class InvalidKeyException : public exception
{
    public:

    const char* what() const noexcept
    {
        return "A credential access was requested without a valid key";
    }
};

class KeyGenerationException : public exception
{
    public:

    const char* what() const noexcept
    {
        return "Error generating key";
    }
};

//This should rarely happen (if ever) but we wan't to know what went wrong if it does
class KeyTimeoutException : public exception
{
    public:

    const char* what() const noexcept
    {
        return "The master key timed out before the requested operation could be completed";
    }
};

class NotImplementedException : public exception
{
    public:

    NotImplementedException() : errorMessage("Not yet implemented")
    { }

    NotImplementedException(string thing)
    {
        errorMessage = thing + " not yet implemented";
    }

    const char* what() const noexcept
    {
        return errorMessage.c_str();
    }

    private:

    string errorMessage;
};

class NullKeyException : public exception
{
    public:

    const char* what() const noexcept
    {
        return "A null master key was specified to the constructor of an object that needs a valid master key reference";
    }

};
