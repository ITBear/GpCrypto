#include <GpCrypto/GpCryptoUtils/GpCryptoFileUtils.hpp>
#include <GpCrypto/GpCryptoCore/Encryption/GpEncryptionUtils_XChaCha20_Poly1305.hpp>
#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Sha2.hpp>
#include <GpCore2/GpUtils/Other/GpRAIIonDestruct.hpp>
#include <GpCore2/GpUtils/Files/GpFileUtils.hpp>
#include <GpCore2/GpUtils/Streams/GpByteWriterStorageFixedSize.hpp>

#include <boost/iostreams/device/mapped_file.hpp>

namespace GPlatform {

void    GpCryptoFileUtils::SEncrypt
(
    const std::string_view          aFileNameSrc,
    const std::string_view          aFileNameDst,
    const std::string_view          aPassword,
    const DstWriteMode              aDstWriteMode,
    const FormatVersion             aFormatVersion,
    const CryptoAlgo                aCryptoAlgo,
    const size_t                    aMaxChunkSize,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    // Check password
    THROW_COND_GP
    (
        !aPassword.empty(),
        "Password is empty"_sv
    );

    // Check file names are not equal
    THROW_COND_GP
    (
        aFileNameSrc != aFileNameDst,
        [aFileNameSrc]()
        {
            return fmt::format
            (
                "The source file name is equal to the destination: '{}'",
                aFileNameSrc
            );
        }
    );

    // Try to open SRC file for reading
    THROW_COND_GP
    (
        GpFileUtils::SIsExists(aFileNameSrc),
        [aFileNameSrc]()
        {
            return fmt::format
            (
                "File not found '{}'",
                aFileNameSrc
            );
        }
    );

    const size_t srcFileSize = NumOps::SConvert<size_t>(GpFileUtils::SSize(aFileNameSrc).Value());

    boost::iostreams::mapped_file_source mappedFileSrc;
    mappedFileSrc.open(std::string{aFileNameSrc});

    THROW_COND_GP
    (
        mappedFileSrc.is_open(),
        [aFileNameSrc]()
        {
            return fmt::format
            (
                "Failed to open file '{}'",
                aFileNameSrc
            );
        }
    );

    GpSpanByteR         fileDataPtrSrc{std::data(mappedFileSrc), std::size(mappedFileSrc)};
    GpByteReaderStorage readerStorage{fileDataPtrSrc};
    GpByteReader        reader{readerStorage};

    GpRAIIonDestruct mappedFileSrcClose
    {
        [&]()
        {
            mappedFileSrc.close();
        }
    };

    // Try to open DST file for writing (considering aDstWriteMode)
    if (aDstWriteMode == DstWriteMode::THROW_IF_EXIST)
    {
        THROW_COND_GP
        (
            GpFileUtils::SIsExists(aFileNameDst) == false,
            [aFileNameDst]()
            {
                return fmt::format
                (
                    "Destination file '{}' already exists",
                    aFileNameDst
                );
            }
        );
    }

    const size_t encryptedSize = SEncryptedSize(aFormatVersion, srcFileSize, aMaxChunkSize);

    boost::iostreams::mapped_file_params mappedFileParamsDst;
    mappedFileParamsDst.path            = std::string{aFileNameDst};
    mappedFileParamsDst.flags           = boost::iostreams::mapped_file::mapmode::readwrite;
    mappedFileParamsDst.offset          = 0;
    mappedFileParamsDst.length          = encryptedSize;
    mappedFileParamsDst.new_file_size   = NumOps::SConvert<boost::iostreams::stream_offset>(encryptedSize);
    mappedFileParamsDst.hint            = nullptr;

    boost::iostreams::mapped_file_sink mappedFileDst;
    mappedFileDst.open(mappedFileParamsDst);

    THROW_COND_GP
    (
        mappedFileDst.is_open(),
        [aFileNameDst]()
        {
            return fmt::format
            (
                "Failed to open file '{}'",
                aFileNameDst
            );
        }
    );

    GpByteWriterStorageFixedSize    writerStorage{GpSpanByteRW{std::data(mappedFileDst), std::size(mappedFileDst)}};
    GpByteWriter                    writer{writerStorage};

    GpRAIIonDestruct mappedFileDstClose
    {
        [&]()
        {
            mappedFileDst.close();
        }
    };

    // Write header
    EncryptedFileHeader::SP fileHeaderSP = SMakeHeader
    (
        aFormatVersion,
        aCryptoAlgo,
        fileDataPtrSrc,
        aMaxChunkSize,
        aStopFlag,
        aEventChannelOpt
    );

    SValidateHeader(fileHeaderSP.Vn());
    SWriteHeader(writer, fileHeaderSP.Vn());

    // Encrypt
    SEncrypt
    (
        reader,
        writer,
        aPassword,
        fileHeaderSP.Vn(),
        aStopFlag,
        aEventChannelOpt
    );
}

void    GpCryptoFileUtils::SDecrypt
(
    const std::string_view          aFileNameSrc,
    const std::string_view          aFileNameDst,
    const std::string_view          aPassword,
    const DstWriteMode              aDstWriteMode,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    // Check password
    THROW_COND_GP
    (
        !aPassword.empty(),
        "Password is empty"_sv
    );

    // Check file names are not equal
    THROW_COND_GP
    (
        aFileNameSrc != aFileNameDst,
        [aFileNameSrc]()
        {
            return fmt::format
            (
                "The source file name is equal to the destination: '{}'",
                aFileNameSrc
            );
        }
    );

    // Try to open SRC file for reading
    THROW_COND_GP
    (
        GpFileUtils::SIsExists(aFileNameSrc),
        [aFileNameSrc]()
        {
            return fmt::format
            (
                "File not found '{}'",
                aFileNameSrc
            );
        }
    );

    boost::iostreams::mapped_file_source mappedFileSrc;
    mappedFileSrc.open(std::string{aFileNameSrc});

    THROW_COND_GP
    (
        mappedFileSrc.is_open(),
        [aFileNameSrc]()
        {
            return fmt::format
            (
                "Failed to open file '{}'",
                aFileNameSrc
            );
        }
    );

    GpByteReaderStorage readerStorage{GpSpanByteR{std::data(mappedFileSrc), std::size(mappedFileSrc)}};
    GpByteReader        reader{readerStorage};

    GpRAIIonDestruct mappedFileSrcClose
    {
        [&]()
        {
            mappedFileSrc.close();
        }
    };

    // Read header
    EncryptedFileHeader::SP     headerSP    = SReadHeader(reader);
    const EncryptedFileHeader&  header      = headerSP.Vn();

    SValidateHeader(header);

    // Try to open DST file for writing (considering aDstWriteMode)
    if (aDstWriteMode == DstWriteMode::THROW_IF_EXIST)
    {
        THROW_COND_GP
        (
            GpFileUtils::SIsExists(aFileNameDst) == false,
            [aFileNameDst]()
            {
                return fmt::format
                (
                    "Destination file '{}' already exists",
                    aFileNameDst
                );
            }
        );
    }

    boost::iostreams::mapped_file_params mappedFileParamsDst;
    mappedFileParamsDst.path            = std::string{aFileNameDst};
    mappedFileParamsDst.flags           = boost::iostreams::mapped_file::mapmode::readwrite;
    mappedFileParamsDst.offset          = 0;
    mappedFileParamsDst.length          = header.iFileSize;
    mappedFileParamsDst.new_file_size   = NumOps::SConvert<boost::iostreams::stream_offset>(header.iFileSize);
    mappedFileParamsDst.hint            = nullptr;

    boost::iostreams::mapped_file_sink mappedFileDst;
    mappedFileDst.open(mappedFileParamsDst);

    THROW_COND_GP
    (
        mappedFileDst.is_open(),
        [aFileNameDst]()
        {
            return fmt::format
            (
                "Failed to open file '{}'",
                aFileNameDst
            );
        }
    );

    GpSpanByteRW                    mappedFileDstDataPtr{std::data(mappedFileDst), std::size(mappedFileDst)};
    GpByteWriterStorageFixedSize    writerStorage{mappedFileDstDataPtr};
    GpByteWriter                    writer{writerStorage};

    GpRAIIonDestruct mappedFileDstClose
    {
        [&]()
        {
            mappedFileDst.close();
        }
    };

    // Decrypt
    SDecrypt(reader, writer, aPassword, header, aStopFlag, aEventChannelOpt);

    // Validate data after decrypt
    SValidateDecrypt(header, mappedFileDstDataPtr, aStopFlag, aEventChannelOpt);
}

size_t  GpCryptoFileUtils::SEncryptedSize
(
    const FormatVersion aFormatVersion,
    const size_t        aSrcFileSize,
    const size_t        aMaxChunkSize
)
{
    THROW_COND_GP
    (
        aFormatVersion == FormatVersion::V1,
        [aFormatVersion]()
        {
            return fmt::format
            (
                "Unsupported format version {:x}",
                u_int_64(aFormatVersion)
            );
        }
    );

    return NumOps::SAdd
    (
        SHeaderSize(aFormatVersion),
        GpEncryptionUtils_XChaCha20_Poly1305::SEncryptTotalSize(aSrcFileSize, aMaxChunkSize)
    );
}

void    GpCryptoFileUtils::SEncrypt
(
    GpByteReader&                   aReader,
    GpByteWriter&                   aWriter,
    std::string_view                aPassword,
    const EncryptedFileHeader&      aHeader,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    if (aEventChannelOpt.has_value())
    {
        aEventChannelOpt.value().get().PushEvent(ProcessStageEvent::FILE_ENCRYPTION);
    }

    THROW_COND_GP
    (
        aHeader.iFormatVersion == FormatVersion::V1,
        [&aHeader]()
        {
            return fmt::format
            (
                "Unsupported format version {:x}",
                u_int_64(aHeader.iFormatVersion)
            );
        }
    );

    const EncryptedFileHeader_V1& header = static_cast<const EncryptedFileHeader_V1&>(aHeader);

    switch (aHeader.iCryptoAlgo)
    {
        case CryptoAlgo::XCHACHA20_POLY1305:
        {
            GpEncryptionUtils_XChaCha20_Poly1305::SEncrypt
            (
                aReader,
                aWriter,
                header.iMaxChunkSize,
                aPassword,
                header.iSalt.AsStringView(),
                aStopFlag,
                aEventChannelOpt
            );
        } break;
        case CryptoAlgo::AES_256:
        {
            THROW_GP("AES-256 cryptographic algorithm is not supported yet");
        } break;
        default:
        {
            THROW_GP("Unknown cryptographic algorithm");
        }
    }
}

void    GpCryptoFileUtils::SDecrypt
(
    GpByteReader&                   aReader,
    GpByteWriter&                   aWriter,
    std::string_view                aPassword,
    const EncryptedFileHeader&      aHeader,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    if (aEventChannelOpt.has_value())
    {
        aEventChannelOpt.value().get().PushEvent(ProcessStageEvent::FILE_DECRYPTION);
    }

    THROW_COND_GP
    (
        aHeader.iFormatVersion == FormatVersion::V1,
        [&aHeader]()
        {
            return fmt::format
            (
                "Unsupported format version {:x}",
                u_int_64(aHeader.iFormatVersion)
            );
        }
    );

    const EncryptedFileHeader_V1& header = static_cast<const EncryptedFileHeader_V1&>(aHeader);

    switch (aHeader.iCryptoAlgo)
    {
        case CryptoAlgo::XCHACHA20_POLY1305:
        {
            GpEncryptionUtils_XChaCha20_Poly1305::SDecrypt
            (
                aReader,
                aWriter,
                header.iMaxChunkSize,
                aPassword,
                header.iSalt.AsStringView(),
                aStopFlag,
                aEventChannelOpt
            );
        } break;
        case CryptoAlgo::AES_256:
        {
            THROW_GP("AES-256 cryptographic algorithm is not supported yet");
        } break;
        default:
        {
            THROW_GP("Unknown cryptographic algorithm");
        }
    }
}

void    GpCryptoFileUtils::SValidateDecrypt
(
    const EncryptedFileHeader&      aHeader,
    GpSpanByteRW                    aFileDstDataPtr,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    THROW_COND_GP
    (
        aHeader.iFormatVersion == FormatVersion::V1,
        [&aHeader]()
        {
            return fmt::format
            (
                "Unsupported format version {:x}",
                u_int_64(aHeader.iFormatVersion)
            );
        }
    );

    const EncryptedFileHeader_V1& header = static_cast<const EncryptedFileHeader_V1&>(aHeader);

    // Check hashsum
    {
        if (aEventChannelOpt.has_value())
        {
            aEventChannelOpt.value().get().PushEvent(ProcessStageEvent::HASH_CALCULATION);
        }

        const GpCryptoHash_Sha2::Res256T fileHash = GpCryptoHash_Sha2::S_256
        (
            aFileDstDataPtr,
            header.iMaxChunkSize,
            aStopFlag,
            aEventChannelOpt
        );

        THROW_COND_GP
        (
            GpSpanByteR{fileHash}.IsEqual(header.iFileHash),
            [&header, &fileHash]()
            {
                return fmt::format
                (
                    "SHA256 hash '{}' of the decrypted file does not match the hash set in the header '{}'",
                    StrOps::SFromBytesHex(fileHash),
                    StrOps::SFromBytesHex(header.iFileHash)
                );
            }
        );
    }
}

GpCryptoFileUtils::EncryptedFileHeader::SP  GpCryptoFileUtils::SMakeHeader
(
    const FormatVersion             aFormatVersion,
    const CryptoAlgo                aCryptoAlgo,
    GpSpanByteR                     aFileDataPtr,
    const size_t                    aMaxChunkSize,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    THROW_COND_GP
    (
        aFormatVersion == FormatVersion::V1,
        [aFormatVersion]()
        {
            return fmt::format
            (
                "Unsupported format version {:x}",
                u_int_64(aFormatVersion)
            );
        }
    );

    EncryptedFileHeader_V1::SP  headerSP    = MakeSP<EncryptedFileHeader_V1>();
    EncryptedFileHeader_V1&     header      = headerSP.V();

    header.iFlags           = 0;
    header.iFormatVersion   = FormatVersion::V1;
    header.iCryptoAlgo      = aCryptoAlgo;
    header.iFileSize        = aFileDataPtr.Count();
    header.iMaxChunkSize    = aMaxChunkSize;

    // Calculate hash
    {
        if (aEventChannelOpt.has_value())
        {
            aEventChannelOpt.value().get().PushEvent(ProcessStageEvent::HASH_CALCULATION);
        }

        header.iFileHash = GpCryptoHash_Sha2::S_256
        (
            aFileDataPtr,
            aMaxChunkSize,
            aStopFlag,
            aEventChannelOpt
        );
    }

    header.iSalt            = GpUUID::SGenRandomV4();

    return headerSP;
}

size_t  GpCryptoFileUtils::SHeaderSize (const FormatVersion aFormatVersion)
{
    size_t headerSize =
          sizeof(EncryptedFileHeader::iName)
        + sizeof(EncryptedFileHeader::iFlags)
        + sizeof(EncryptedFileHeader::iFormatVersion)
        + sizeof(EncryptedFileHeader::iCryptoAlgo)
        + sizeof(EncryptedFileHeader::iFileSize);

    THROW_COND_GP
    (
        aFormatVersion == FormatVersion::V1,
        [aFormatVersion]()
        {
            return fmt::format
            (
                "Unsupported format version {:x}",
                u_int_64(aFormatVersion)
            );
        }
    );

    headerSize +=
          sizeof(EncryptedFileHeader_V1::iMaxChunkSize)
        + sizeof(EncryptedFileHeader_V1::iFileHash)
        + sizeof(EncryptedFileHeader_V1::iSalt);

    return headerSize;
}

GpCryptoFileUtils::EncryptedFileHeader::SP  GpCryptoFileUtils::SReadHeader (GpByteReader& aReader)
{
    // Read fixed header parts

    // Name
    GpSpanByteR name = aReader.Bytes(sizeof(EncryptedFileHeader::iName));

    // Flags
    const u_int_64 flags = aReader.UI64();

    // Format version
    const FormatVersion formatVersion = FormatVersion{aReader.UI64()};

    // CryptoAlgo
    const CryptoAlgo cryptoAlgo = CryptoAlgo{aReader.UI64()};

    // File size
    const u_int_64 fileSize = aReader.UI64();

    // Check format version
    THROW_COND_GP
    (
        formatVersion == FormatVersion::V1,
        [formatVersion]()
        {
            return fmt::format
            (
                "Unsupported format version {:x}",
                u_int_64(formatVersion)
            );
        }
    );

    // Read header v1
    EncryptedFileHeader_V1::SP  headerSP    = MakeSP<EncryptedFileHeader_V1>();
    EncryptedFileHeader_V1&     header      = headerSP.Vn();

    // Fixed header parts
    {
        // Name
        GpSpanByteRW{header.iName}.CopyFrom(name);

        // Flags
        header.iFlags = flags;

        // Format version
        header.iFormatVersion = formatVersion;

        // Crypto algo
        header.iCryptoAlgo = cryptoAlgo;

        // File size
        header.iFileSize = fileSize;
    }

    // Max chunk size
    header.iMaxChunkSize = aReader.UI64();

    // SHA256 src file hash
    GpSpanByteRW{header.iFileHash}.CopyFrom
    (
        aReader.Bytes(sizeof(EncryptedFileHeader_V1::iFileHash))
    );

    // Salt
    GpSpanByteRW{header.iSalt.Data()}.CopyFrom
    (
        aReader.Bytes(sizeof(EncryptedFileHeader_V1::iSalt))
    );

    return headerSP;
}

void    GpCryptoFileUtils::SValidateHeader (const EncryptedFileHeader& aHeader)
{
    // Check name
    THROW_COND_GP
    (
        GpSpanByteR{aHeader.iName}.IsEqual(EncryptedFileHeader{}.iName),
        "Wrong header name"_sv
    );

    // Check flags
    THROW_COND_GP
    (
        aHeader.iFlags == 0,
        "Wrong flags value"_sv
    );

    // Check format version
    THROW_COND_GP
    (
        aHeader.iFormatVersion == FormatVersion::V1,
        [&aHeader]()
        {
            return fmt::format
            (
                "Unsupported format version {:x}",
                u_int_64(aHeader.iFormatVersion)
            );
        }
    );

    // Check file size
    THROW_COND_GP
    (
        aHeader.iFileSize > (SHeaderSize(aHeader.iFormatVersion) + 1),
        "Wrong file size"_sv
    );
}

void    GpCryptoFileUtils::SWriteHeader
(
    GpByteWriter&               aWriter,
    const EncryptedFileHeader&  aHeader
)
{
    // Write fixed header parts

    // Name
    aWriter.Bytes(aHeader.iName);

    // Flags
    aWriter.UI64(aHeader.iFlags);

    // Format version
    aWriter.UI64(u_int_64(aHeader.iFormatVersion));

    // CryptoAlgo
    aWriter.UI64(u_int_64(aHeader.iCryptoAlgo));

    // File size
    aWriter.UI64(aHeader.iFileSize);

    // Check format version
    THROW_COND_GP
    (
        aHeader.iFormatVersion == FormatVersion::V1,
        [&aHeader]()
        {
            return fmt::format
            (
                "Unsupported format version {:x}",
                u_int_64(aHeader.iFormatVersion)
            );
        }
    );

    // Write header v1
    const EncryptedFileHeader_V1& header = static_cast<const EncryptedFileHeader_V1&>(aHeader);

    // Max chunk size
    aWriter.UI64(header.iMaxChunkSize);

    // SHA256 src file hash
    aWriter.Bytes(header.iFileHash);

    // Salt
    aWriter.Bytes(header.iSalt.AsStringView());
}

}// namespace GPlatform
