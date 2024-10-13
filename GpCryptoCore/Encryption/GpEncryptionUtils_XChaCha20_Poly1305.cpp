#include <GpCrypto/GpCryptoCore/Encryption/GpEncryptionUtils_XChaCha20_Poly1305.hpp>
#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_KDF_Passwd.hpp>
#include <GpCrypto/GpCryptoCore/Utils/GpByteWriterStorageSecure.hpp>
#include <GpCore2/GpUtils/Streams/GpByteWriterStorageByteArray.hpp>
#include <GpCore2/GpUtils/EventBus/Events/GpDataProcessUpdateEvent.hpp>

//GP_WARNING_PUSH()
//GP_WARNING_DISABLE_GCC(duplicated-branches)

#if defined(RELEASE_BUILD_STATIC)
#   define SODIUM_STATIC
#endif

#include <libsodium/sodium.h>

//GP_WARNING_POP()

namespace GPlatform {

size_t  GpEncryptionUtils_XChaCha20_Poly1305::SEncryptTotalSize
(
    const size_t aSrcSize,
    const size_t aMaxChunkSize
)
{
    // Check aSrcSize
    THROW_COND_GP
    (
        aSrcSize > 0,
        [aSrcSize]()
        {
            return fmt::format
            (
                "'aSrcSize' must be > 0, but the actual value is {}",
                aSrcSize
            );
        }
    );

    // Check aMaxChunkSize
    THROW_COND_GP
    (
        aMaxChunkSize > 0,
        [aMaxChunkSize]()
        {
            return fmt::format
            (
                "'aMaxChunkSize' must be > 0, but the actual value is {}",
                aMaxChunkSize
            );
        }
    );

    const size_t fullChunksCount    = aSrcSize / aMaxChunkSize;
    const size_t notFullChunksCount = (aSrcSize % aMaxChunkSize) > 0 ? 1 : 0;

    const size_t fullChunksSize     = NumOps::SMul<size_t>(fullChunksCount, NumOps::SAdd<size_t>(aMaxChunkSize, crypto_secretstream_xchacha20poly1305_ABYTES));
    size_t notFullChunksSize        = 0;

    if (notFullChunksCount > 0)
    {
        notFullChunksSize = NumOps::SAdd<size_t>((aSrcSize % aMaxChunkSize), crypto_secretstream_xchacha20poly1305_ABYTES);
    }

    const size_t payloadSize = NumOps::SAdd<size_t>(fullChunksSize, notFullChunksSize);

    return NumOps::SAdd<size_t>(crypto_secretstream_xchacha20poly1305_HEADERBYTES, payloadSize);
}

GpBytesArray    GpEncryptionUtils_XChaCha20_Poly1305::SEncrypt
(
    GpSpanByteR                     aSrcData,
    const size_t                    aMaxChunkSize,
    GpSpanCharR                     aPassword,
    GpSpanCharR                     aSalt,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    GpSecureStorage::CSP key = SPasswordToKey(aPassword, aSalt);

    GpByteReaderStorage srcDataReaderStorage{aSrcData};
    GpByteReader        srcDataReader{srcDataReaderStorage};

    GpBytesArray encriptedData;
    {
        encriptedData.resize(aSrcData.Count());

        GpByteWriterStorageByteArray    encriptedDataWriterStorage{encriptedData};
        GpByteWriter                    encriptedDataWriter{encriptedDataWriterStorage};

        GpEncryptionUtils_XChaCha20_Poly1305::SEncrypt
        (
            srcDataReader,
            encriptedDataWriter,
            aMaxChunkSize,
            key.V().ViewR().R(),
            aStopFlag,
            aEventChannelOpt
        );

        encriptedDataWriter.OnEnd();
    }

    return encriptedData;
}

GpSecureStorage::CSP    GpEncryptionUtils_XChaCha20_Poly1305::SDecrypt
(
    GpSpanByteR                     aSrcData,
    const size_t                    aMaxChunkSize,
    GpSpanCharR                     aPassword,
    GpSpanCharR                     aSalt,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    GpSecureStorage::CSP key = SPasswordToKey(aPassword, aSalt);

    GpByteReaderStorage srcDataReaderStorage{aSrcData};
    GpByteReader        srcDataReader{srcDataReaderStorage};

    GpSecureStorage::SP     decriptedDataSP = MakeSP<GpSecureStorage>();
    GpSecureStorage&        decriptedData   = decriptedDataSP.V();
    decriptedData.Reserve(aSrcData.Count());

    GpByteWriterStorageSecure   decriptedDataWriterStorage{decriptedData};
    GpByteWriter                decriptedDataWriter{decriptedDataWriterStorage};

    GpEncryptionUtils_XChaCha20_Poly1305::SDecrypt
    (
        srcDataReader,
        decriptedDataWriter,
        aMaxChunkSize,
        key.V().ViewR().R(),
        aStopFlag,
        aEventChannelOpt
    );

    return decriptedDataSP;
}

void    GpEncryptionUtils_XChaCha20_Poly1305::SEncrypt
(
    GpByteReader&                   aReader,
    GpByteWriter&                   aWriter,
    const size_t                    aMaxChunkSize,
    GpSpanCharR                     aPassword,
    GpSpanCharR                     aSalt,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    GpSecureStorage::CSP key = SPasswordToKey(aPassword, aSalt);

    GpEncryptionUtils_XChaCha20_Poly1305::SEncrypt
    (
        aReader,
        aWriter,
        aMaxChunkSize,
        key.V().ViewR().R(),
        aStopFlag,
        aEventChannelOpt
    );
}

void    GpEncryptionUtils_XChaCha20_Poly1305::SDecrypt
(
    GpByteReader&                   aReader,
    GpByteWriter&                   aWriter,
    const size_t                    aMaxChunkSize,
    GpSpanCharR                     aPassword,
    GpSpanCharR                     aSalt,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    GpSecureStorage::CSP key = SPasswordToKey(aPassword, aSalt);

    GpEncryptionUtils_XChaCha20_Poly1305::SDecrypt
    (
        aReader,
        aWriter,
        aMaxChunkSize,
        key.V().ViewR().R(),
        aStopFlag,
        aEventChannelOpt
    );
}

void    GpEncryptionUtils_XChaCha20_Poly1305::SEncrypt
(
    GpByteReader&                   aReader,
    GpByteWriter&                   aWriter,
    const size_t                    aMaxChunkSize,
    GpSpanByteR                     aKey,
    std::atomic_flag&               aStopFlag,
    [[maybe_unused]] GpEventChannelAny::C::Opt::Ref aEventChannelOpt
)
{
    const u_int_64  encryptedDataTotalSize      = aReader.SizeLeft();
    u_int_64        encryptedDataProcessedSize  = 0;

    THROW_COND_GP
    (
        aKey.Count() >= size_t{crypto_secretstream_xchacha20poly1305_KEYBYTES},
        "Wrong key length"_sv
    );

    crypto_secretstream_xchacha20poly1305_state encryptState;

    // Process header
    std::array<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES> encryptHeader;

    const auto initRes = crypto_secretstream_xchacha20poly1305_init_push
    (
        &encryptState,
        std::data(encryptHeader),
        aKey.PtrAs<const unsigned char*>()
    );

    THROW_COND_GP
    (
        initRes == 0,
        "crypto_secretstream_xchacha20poly1305_init_push return error"_sv
    );

    aWriter.Bytes(encryptHeader);

    // Process chunks
    GpDataProcessUpdateEventEmitter dataProcessUpdateEventEmitter{encryptedDataTotalSize};

    while (aReader.SizeLeft() > 0)
    {
        if (aStopFlag.test() == true) [[unlikely]]
        {
            THROW_GP("Process was interrupted");
        }

        const size_t        readerSizeLeft      = aReader.SizeLeft();
        const size_t        srcChunkSize        = std::min(readerSizeLeft, aMaxChunkSize);
        GpSpanByteR         srcChunkPtr         = aReader.Bytes(srcChunkSize);
        const size_t        encryptChunkSize    = NumOps::SAdd<size_t>(srcChunkSize, crypto_secretstream_xchacha20poly1305_ABYTES);
        GpSpanByteRW        encryptChunkPtr     = aWriter.SubspanThenOffsetAdd(encryptChunkSize);
        const unsigned char tag                 = (aReader.SizeLeft() == 0) ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

        const auto pushRes = crypto_secretstream_xchacha20poly1305_push
        (
            &encryptState,
            reinterpret_cast<unsigned char*>(std::data(encryptChunkPtr)),
            nullptr,
            srcChunkPtr.PtrAs<const unsigned char*>(),
            srcChunkPtr.Count(),
            nullptr,
            0,
            tag
        );

        THROW_COND_GP
        (
            pushRes == 0,
            "crypto_secretstream_xchacha20poly1305_push return error"_sv
        );

        encryptedDataProcessedSize += srcChunkSize;

        if (aEventChannelOpt.has_value())
        {
            dataProcessUpdateEventEmitter.Update
            (
                encryptedDataProcessedSize,
                aEventChannelOpt.value().get()
            );
        }
    }

    THROW_COND_GP
    (
        aReader.SizeLeft() == 0,
        [&aReader]()
        {
            return fmt::format
            (
                "Not all bytes were read from aReader, bytes left count: {}",
                aReader.SizeLeft()
            );
        }
    );

    THROW_COND_GP
    (
        aWriter.SizeLeft() == 0,
        [&aWriter]()
        {
            return fmt::format
            (
                "A writer has bytes left to write, count: {}",
                aWriter.SizeLeft()
            );
        }
    );
}

void    GpEncryptionUtils_XChaCha20_Poly1305::SDecrypt
(
    GpByteReader&                   aReader,
    GpByteWriter&                   aWriter,
    const size_t                    aMaxChunkSize,
    GpSpanByteR                     aKey,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    const u_int_64  decryptedDataTotalSize      = aWriter.SizeLeft();
    u_int_64        decryptedDataProcessedSize  = 0;

    THROW_COND_GP
    (
        aKey.Count() >= size_t(crypto_secretstream_xchacha20poly1305_KEYBYTES),
        "Wrong key length"_sv
    );

    crypto_secretstream_xchacha20poly1305_state encryptState;

    // Process header
    std::array<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES> encryptHeader;
    GpSpanByteRW{encryptHeader}.CopyFrom
    (
        aReader.Bytes(std::size(encryptHeader))
    );

    const auto initRes = crypto_secretstream_xchacha20poly1305_init_pull
    (
        &encryptState,
        std::data(encryptHeader),
        aKey.PtrAs<const unsigned char*>()
    );

    THROW_COND_GP
    (
        initRes == 0,
        "crypto_secretstream_xchacha20poly1305_init_pull return error"_sv
    );

    // Process chunks
    unsigned char tag = 0;

    GpDataProcessUpdateEventEmitter dataProcessUpdateEventEmitter{decryptedDataTotalSize};

    while (   (aReader.SizeLeft() > 0)
           || (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL))
    {
        if (aStopFlag.test() == true) [[unlikely]]
        {
            THROW_GP("Process was interrupted");
        }

        const size_t    readerSizeLeft      = aReader.SizeLeft();
        const size_t    encryptChunkSize    = std::min(readerSizeLeft, aMaxChunkSize + crypto_secretstream_xchacha20poly1305_ABYTES);

        THROW_COND_GP
        (
            encryptChunkSize >= (crypto_secretstream_xchacha20poly1305_ABYTES + 1),
            []()
            {
                return fmt::format
                (
                    "`encryptChunkSize` < {}",
                    crypto_secretstream_xchacha20poly1305_ABYTES + 1
                );
            }
        );

        GpSpanByteR     encryptChunkPtr     = aReader.Bytes(encryptChunkSize);
        const size_t    decryptChunkSize    = encryptChunkSize - crypto_secretstream_xchacha20poly1305_ABYTES;
        GpSpanByteRW    decryptChunkPtr     = aWriter.SubspanThenOffsetAdd(decryptChunkSize);

        tag = 0;

        const auto pullRes = crypto_secretstream_xchacha20poly1305_pull
        (
            &encryptState,
            decryptChunkPtr.PtrAs<unsigned char*>(),
            nullptr,
            &tag,
            encryptChunkPtr.PtrAs<const unsigned char *>(),
            encryptChunkPtr.Count(),
            nullptr,
            0
        );

        decryptedDataProcessedSize += decryptChunkSize;

        THROW_COND_GP
        (
            pullRes == 0,
            "crypto_secretstream_xchacha20poly1305_pull return error"_sv
        );

        if (aEventChannelOpt.has_value())
        {
            dataProcessUpdateEventEmitter.Update
            (
                decryptedDataProcessedSize,
                aEventChannelOpt.value().get()
            );
        }
    }

    THROW_COND_GP
    (
        tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL,
        [tag]()
        {
            return fmt::format
            (
                "`tag` was expected to be 'crypto_secretstream_xchacha20poly1305_TAG_FINAL==', but the actual value is: {}",
                tag
            );
        }
    );

    THROW_COND_GP
    (
        aReader.SizeLeft() == 0,
        [&aReader]()
        {
            return fmt::format
            (
                "Not all bytes were read from aReader, bytes left count: {}",
                aReader.SizeLeft()
            );
        }
    );

    THROW_COND_GP
    (
        aWriter.SizeLeft() == 0,
        [&aWriter]()
        {
            return fmt::format
            (
                "A writer has bytes left to write, count: {}",
                aWriter.SizeLeft()
            );
        }
    );
}

GpSecureStorage::CSP    GpEncryptionUtils_XChaCha20_Poly1305::SPasswordToKey
(
    GpSpanCharR aPassword,
    GpSpanCharR aSalt
)
{
    // Check password
    THROW_COND_GP
    (
        !aPassword.Empty(),
        "Password is empty"_sv
    );

    return GpCryptoHash_KDF_Passwd::S_H(aPassword, aSalt, 32_byte, 32_MiB);
}

}// namespace GPlatform
