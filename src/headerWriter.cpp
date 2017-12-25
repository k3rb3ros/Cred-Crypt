#include "include/headerWriter.hpp"

headerWriter::headerWriter(masterKey* master_key):
    headerBase(master_key),
    encrypted_(false)
{ /* nop */ }

headerWriter::~headerWriter() noexcept
{
}

bool headerWriter::write(ostream &os)
{
    bool success = false;

    if (mk_->isValid() && this->isValid())
    {
        //prevents the header from getting encrypted mulitple times if multiple calls to write are made
        if (!encrypted_)
        {
            success = encryptHeader();
        }

        if (success)
        {
            //write the header
            os.write((char*)&header_, sizeof(header));
        }

    if (success && os.good()) { success = true; }
    else { success = false; }
    }

    return success;
}

void headerWriter::setCredSize(uint64_t size)
{
    header_.data_size = size;
}

bool headerWriter::encryptHeader()
{
    /* the data section of the header is OCB encrypted with the master key the only way to see
     * the data (of which we have inside knowledge to know what it will look like) is to have
     * the correct key present at header read time.
     */
    bool success = false;
    ocbCtx ctx;
    void* header_data = (void*)&header_.magic_number;

    if (ocbSetup(&ctx, (uint64_t*)mk_->keyBytes(), header_.salt))
    {
        ocbEncrypt(&ctx,
                   header_data,
                   header_data,
                   HEADER_DATA_BYTE_SIZE);

        success = true;
    }

    return success;
}
