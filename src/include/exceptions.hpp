#pragma once

#include <exception>
#include <string>

struct CredentialClearException : public std::exception
{
    const char* what() const noexcept
    {
        return "Error clearing all credentials";
    }
};

struct CredentialNotFoundException : public std::exception
{
    const char* what() const noexcept
    {
        return "The credential could not be found";
    }
};

struct CredentialLoadException : public std::exception
{
    const char* what() const noexcept
    {
        return "An error occured that prevented credentials from being loaded";
    }
};

struct CredentialSaveException : public std::exception
{
    const char* what() const noexcept
    {
        return "An error occured that prevented credentials from being saved";
    }
};

struct DestructiveOperationException : public std::exception
{
    const char* what() const noexcept
    {
        return "An operation was requested that would destroy key information for one or more currently loaded credentials";
    }
};

struct InvalidCredentialException : public std::exception
{
    const char* what() const noexcept
    {
        return "Invalid credential specified";
    }
};

struct InvalidKeyException : public std::exception
{
    const char* what() const noexcept
    {
        return "A credential access was requested without a valid key";
    }
};

struct KeyGenerationException : public std::exception
{
    const char* what() const noexcept
    {
        return "Error generating key";
    }
};

//This should rarely happen (if ever) but we wan't to know what went wrong if it does
struct KeyTimeoutException : public std::exception
{
    const char* what() const noexcept
    {
        return "The master key timed out before the requested operation could be completed";
    }
};

class NotImplementedException : public std::exception
{
    public:

    NotImplementedException() : errorMessage("Not yet implemented")
    { }

    NotImplementedException(const std::string thing)
    {
        errorMessage = thing + " not yet implemented";
    }

    const char* what() const noexcept
    {
        return errorMessage.c_str();
    }

    private:

    std::string errorMessage;
};

struct NullKeyException : public std::exception
{
    const char* what() const noexcept
    {
        return "A null master key was specified to the constructor of an object that needs a valid master key reference";
    }
};

class RandomDataNotAvailableException : public std::exception
{
    const char* what() const noexcept
    {
        return "The program was unable to get acces to random data that it needed to construct a cryptographic primative";
    }
};
