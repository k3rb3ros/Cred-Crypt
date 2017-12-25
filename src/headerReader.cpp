#include "include/headerReader.hpp"

headerReader::headerReader(masterKey* master_key) : headerBase(master_key),
                                                          decrypted_(false),
                                                          read_(false)
{ /*nop*/ }

headerReader::~headerReader() noexcept
{ /*nop*/ }

bool headerReader::read(istream &is)
{
    read_ = false;

    if (is)
    {
        is.read((char*)&header_, sizeof(header));
        /*if there is still data to read and no errors occured then we consider the read a
         * success and copy the salt into the masterKey
         */
        if (is.good())
        {
            read_ = true;
        }
    }

    return read_;
}

bool headerReader::decryptHeaderData()
{
    bool decrypted = false;
    ocbCtx ctx;

    if (ocbSetup(&ctx, (uint64_t*)mk_->keyBytes(), header_.salt))
    {
        /* decrypting out of place allows us to not have to reverse the operation if
        * decrypting fails for whatever reason. So we declare a temp header to store the
        * result of the decryption attempt.
        */
        header tmp_hdr;
        void* enc_data = (void*)&header_.magic_number;
        void* dec_data = (void*)&tmp_hdr.magic_number;

        if (ocbDecrypt(&ctx,
                       enc_data,
                       dec_data,
                       HEADER_DATA_BYTE_SIZE+OCB_TAG_BYTE_SIZE))
        {
            header_.magic_number = tmp_hdr.magic_number;
            header_.data_size = tmp_hdr.data_size;
            header_.version_major = tmp_hdr.version_major;
            header_.version_minor = tmp_hdr.version_minor;
            //clear the tag to prevent leaking information
            for (uint_fast8_t i=0; i<OCB_TAG_WORD_SIZE; ++i) { header_.tag[i] = 0; }

            decrypted = true;
        }
    }

    return decrypted;
}

bool headerReader::headerIsValid(secStr &pw)
{
    bool valid = false;

    /* only continue if data has been read into the header
     */
    if (read_)
    {
        //try to decrypt the header with the salt from the file and the password from the user
        //generate a master key with the salt in the header and the password provided
        mk_->setSalt(header_.salt); mk_->inputPassword(pw);

        //Because OCB is authenticated a success in decryption implies that
        //the password and salt are correct
        if (!decrypted_ && mk_->isValid())
        {
            decrypted_ = decryptHeaderData();
        }

        //we verify the magic number to make sure we have actually decrypted a header
        if (decrypted_)
        {
            valid = (header_.magic_number == MAGIC_NUMBER);
        }
        else //decryption failed so clear the salt and pw from the master key
        {
            mk_->clearSalt();
            mk_->clearKey();
        }
    }

    return valid;
}

uint64_t headerReader::getCredsSize()
{
    return header_.data_size;
}
