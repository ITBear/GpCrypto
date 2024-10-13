#pragma once

#include <GpCrypto/Config/GpConfigCrypto.hpp>

#if defined(GP_CRYPTO_USE_FILE_UTILS)

#include <GpCrypto/GpCryptoUtils/GpCryptoUtils_global.hpp>
#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Sha2.hpp>
#include <GpCore2/GpUtils/Macro/GpMacroClass.hpp>
#include <GpCore2/GpUtils/Streams/GpByteReader.hpp>
#include <GpCore2/GpUtils/Streams/GpByteWriter.hpp>
#include <GpCore2/GpUtils/Types/UIDs/GpUUID.hpp>

namespace GPlatform {

class GP_CRYPTO_UTILS_API GpCryptoFileUtils
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoFileUtils)

    using Sha256 = GpCryptoHash_Sha2::Res256T;

    enum class DstWriteMode
    {
        OVERRIDE_EXISTING,
        THROW_IF_EXIST
    };

    enum class FormatVersion: u_int_64
    {
        V1 = 0xFF00000000001000
    };

    enum class CryptoAlgo: u_int_64
    {
        XCHACHA20_POLY1305  = 0xCA00000000001000,
        AES_256             = 0xCA00000000002000
    };

    enum class ProcessStageEvent
    {
        HASH_CALCULATION,
        FILE_ENCRYPTION,
        FILE_DECRYPTION
    };

    class EncryptedFileHeader
    {
    public:
        CLASS_DD(EncryptedFileHeader)

    public:
        std::array<char, 16>    iName           = {'G','p','C','r','y','p','t','o','F','i','l','e','U','t','i','l'};
        u_int_64                iFlags          = 0; // Reserved for future use
        FormatVersion           iFormatVersion  = FormatVersion::V1;
        CryptoAlgo              iCryptoAlgo     = CryptoAlgo::XCHACHA20_POLY1305;
        u_int_64                iFileSize       = 0;
    };

    class EncryptedFileHeader_V1 final: public EncryptedFileHeader
    {
    public:
        CLASS_DD(EncryptedFileHeader_V1)

    public:     
        u_int_64    iMaxChunkSize   = 0;
        Sha256      iFileHash;
        GpUUID      iSalt;
    };

public:
    static void                     SEncrypt            (std::string_view               aFileNameSrc,
                                                         std::string_view               aFileNameDst,
                                                         std::string_view               aPassword,
                                                         DstWriteMode                   aDstWriteMode,
                                                         FormatVersion                  aFormatVersion,
                                                         CryptoAlgo                     aCryptoAlgo,
                                                         size_t                         aMaxChunkSize,
                                                         std::atomic_flag&              aStopFlag,
                                                         GpEventChannelAny::C::Opt::Ref aEventChannelOpt);
    static void                     SDecrypt            (std::string_view               aFileNameSrc,
                                                         std::string_view               aFileNameDst,
                                                         std::string_view               aPassword,
                                                         DstWriteMode                   aDstWriteMode,
                                                         std::atomic_flag&              aStopFlag,
                                                         GpEventChannelAny::C::Opt::Ref aEventChannelOpt);

private:
    static size_t                   SEncryptedSize      (FormatVersion      aFormatVersion,
                                                         size_t             aSrcFileSize,
                                                         size_t             aMaxChunkSize);
    static void                     SEncrypt            (GpByteReader&                  aReader,
                                                         GpByteWriter&                  aWriter,
                                                         std::string_view               aPassword,
                                                         const EncryptedFileHeader&     aHeader,
                                                         std::atomic_flag&              aStopFlag,
                                                         GpEventChannelAny::C::Opt::Ref aEventChannelOpt);
    static void                     SDecrypt            (GpByteReader&                  aReader,
                                                         GpByteWriter&                  aWriter,
                                                         std::string_view               aPassword,
                                                         const EncryptedFileHeader&     aHeader,
                                                         std::atomic_flag&              aStopFlag,
                                                         GpEventChannelAny::C::Opt::Ref aEventChannelOpt);
    static void                     SValidateDecrypt    (const EncryptedFileHeader&     aHeader,
                                                         GpSpanByteRW                   aFileDstDataPtr,
                                                         std::atomic_flag&              aStopFlag,
                                                         GpEventChannelAny::C::Opt::Ref aEventChannelOpt);
    static EncryptedFileHeader::SP  SMakeHeader         (FormatVersion                  aFormatVersion,
                                                         CryptoAlgo                     aCryptoAlgo,
                                                         GpSpanByteR                    aFileDataPtr,
                                                         size_t                         aMaxChunkSize,
                                                         std::atomic_flag&              aStopFlag,
                                                         GpEventChannelAny::C::Opt::Ref aEventChannelOpt);
    static size_t                   SHeaderSize         (FormatVersion      aFormatVersion);
    static EncryptedFileHeader::SP  SReadHeader         (GpByteReader&  aReader);
    static void                     SValidateHeader     (const EncryptedFileHeader& aHeader);
    static void                     SWriteHeader        (GpByteWriter&              aWriter,
                                                         const EncryptedFileHeader& aHeader);
};

}// namespace GPlatform

#endif// #if defined(GP_CRYPTO_USE_FILE_UTILS)
