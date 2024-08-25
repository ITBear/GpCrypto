#pragma once

#include <GpCrypto/GpCryptoCore/GpCryptoCore_global.hpp>
#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>
#include <GpCore2/GpUtils/Streams/GpByteReader.hpp>
#include <GpCore2/GpUtils/Streams/GpByteWriter.hpp>
#include <GpCore2/GpUtils/EventBus/GpEventChannelAny.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpEncryptionUtils_XChaCha20_Poly1305
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpEncryptionUtils_XChaCha20_Poly1305)

public:
    static size_t               SEncryptTotalSize   (size_t aSrcSize,
                                                     size_t aMaxChunkSize);

    static GpBytesArray         SEncrypt            (GpSpanByteR                    aSrcData,
                                                     size_t                         aMaxChunkSize,
                                                     GpSpanCharR                    aPassword,
                                                     GpSpanCharR                    aSalt,
                                                     std::atomic_flag&              aStopFlag,
                                                     GpEventChannelAny::C::Opt::Ref aEventChannelOpt);

    static GpSecureStorage::CSP SDecrypt            (GpSpanByteR                    aSrcData,
                                                     size_t                         aMaxChunkSize,
                                                     GpSpanCharR                    aPassword,
                                                     GpSpanCharR                    aSalt,
                                                     std::atomic_flag&              aStopFlag,
                                                     GpEventChannelAny::C::Opt::Ref aEventChannelOpt);

    static void                 SEncrypt            (GpByteReader&                  aReader,
                                                     GpByteWriter&                  aWriter,
                                                     size_t                         aMaxChunkSize,
                                                     GpSpanCharR                    aPassword,
                                                     GpSpanCharR                    aSalt,
                                                     std::atomic_flag&              aStopFlag,
                                                     GpEventChannelAny::C::Opt::Ref aEventChannelOpt);

    static void                 SDecrypt            (GpByteReader&                  aReader,
                                                     GpByteWriter&                  aWriter,
                                                     size_t                         aMaxChunkSize,
                                                     GpSpanCharR                    aPassword,
                                                     GpSpanCharR                    aSalt,
                                                     std::atomic_flag&              aStopFlag,
                                                     GpEventChannelAny::C::Opt::Ref aEventChannelOpt);

    static void                 SEncrypt            (GpByteReader&                  aReader,
                                                     GpByteWriter&                  aWriter,
                                                     size_t                         aMaxChunkSize,
                                                     GpSpanByteR                    aKey,
                                                     std::atomic_flag&              aStopFlag,
                                                     GpEventChannelAny::C::Opt::Ref aEventChannelOpt);

    static void                 SDecrypt            (GpByteReader&                  aReader,
                                                     GpByteWriter&                  aWriter,
                                                     size_t                         aMaxChunkSize,
                                                     GpSpanByteR                    aKey,
                                                     std::atomic_flag&              aStopFlag,
                                                     GpEventChannelAny::C::Opt::Ref aEventChannelOpt);

    static GpSecureStorage::CSP SPasswordToKey      (GpSpanCharR    aPassword,
                                                     GpSpanCharR    aSalt);
};

}// namespace GPlatform
