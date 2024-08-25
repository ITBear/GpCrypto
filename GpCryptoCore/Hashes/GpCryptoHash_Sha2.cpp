#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Sha2.hpp>
#include <GpCore2/GpUtils/EventBus/Events/GpDataProcessUpdateEvent.hpp>
#include <algorithm>

GP_WARNING_PUSH()
GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

GpCryptoHash_Sha2::Res256T  GpCryptoHash_Sha2::S_256 (GpSpanByteR aData)
{
    std::atomic_flag stopFlag = false;

    return S_256
    (
        aData,
        aData.Count(),
        stopFlag,
        std::nullopt
    );
}

void    GpCryptoHash_Sha2::S_256
(
    GpSpanByteR                     aData,
    GpSpanByteRW                    aResOut,
    const size_t                    aMaxChunkSize,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    THROW_COND_GP
    (
        aResOut.Count() == std::tuple_size<Res256T>::value,
        "`aRes` size is not equal to 32"_sv
    );

    const size_t maxChunkSize = aMaxChunkSize;
    GpBytesArray chunkBuffer;
    chunkBuffer.resize(maxChunkSize);

    crypto_hash_sha256_state state;

    THROW_COND_GP
    (
        crypto_hash_sha256_init(&state) == 0,
        "`crypto_hash_sha256_init` returns error"_sv
    );

    const u_int_64  dataTotalSize       = aData.Count();
    u_int_64        dataProcessedSize   = 0;
    const size_t    chunksCount         = (dataTotalSize / maxChunkSize)
                                        + ((dataTotalSize % maxChunkSize) > 0 ? 1 : 0);

    GpDataProcessUpdateEventEmitter dataProcessUpdateEventEmitter{dataTotalSize};

    for (size_t chunkId = 0; chunkId < chunksCount; chunkId++)
    {
        if (aStopFlag.test() == true) [[unlikely]]
        {
            THROW_GP("Process was interrupted");
        }

        const size_t    dataLeftSize        = aData.Count();
        const size_t    dataToProcessSize   = std::min(maxChunkSize, dataLeftSize);
        GpSpanByteR     dataToProcessPtr    = aData.SubspanThenOffsetAdd(dataToProcessSize);

        GpSpanByteRW chunkBufferSpanRW{std::data(chunkBuffer), dataToProcessSize};
        chunkBufferSpanRW.CopyFrom(dataToProcessPtr);

        THROW_COND_GP
        (
            crypto_hash_sha256_update
            (
                &state,
                chunkBufferSpanRW.PtrAs<const unsigned char*>(),
                chunkBufferSpanRW.Count()
            ) == 0,
            "`crypto_hash_sha256_update` returns error"_sv
        );

        dataProcessedSize += dataToProcessSize;

        if (aEventChannelOpt.has_value())
        {
            dataProcessUpdateEventEmitter.Update
            (
                dataProcessedSize,
                aEventChannelOpt.value().get()
            );
        }
    }

    THROW_COND_GP
    (
        crypto_hash_sha256_final(&state, aResOut.PtrAs<unsigned char*>()) == 0,
        "`crypto_hash_sha256_final` returns error"_sv
    );
}

GpCryptoHash_Sha2::Res256T  GpCryptoHash_Sha2::S_256
(
    GpSpanByteR                     aData,
    const size_t                    aMaxChunkSize,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    Res256T         res;
    GpSpanByteRW    r{res};

    S_256(aData, r, aMaxChunkSize, aStopFlag, aEventChannelOpt);

    return res;
}

void    GpCryptoHash_Sha2::S_512
(
    GpSpanByteR                     aData,
    GpSpanByteRW                    aResOut,
    const size_t                    aMaxChunkSize,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    THROW_COND_GP
    (
        aResOut.Count() == std::tuple_size<Res512T>::value,
        "`aRes` size is not equal to 64"_sv
    );

    const size_t maxChunkSize = aMaxChunkSize;

    crypto_hash_sha512_state state;

    THROW_COND_GP
    (
        crypto_hash_sha512_init(&state) == 0,
        "`crypto_hash_sha512_init` returns error"_sv
    );

    const u_int_64  dataTotalSize       = aData.Count();
    u_int_64        dataProcessedSize   = 0;
    const size_t    chunksCount         = (dataTotalSize / maxChunkSize)
                                        + ((dataTotalSize % maxChunkSize) > 0 ? 1 : 0);

    GpDataProcessUpdateEventEmitter dataProcessUpdateEventEmitter{dataTotalSize};

    for (size_t chunkId = 0; chunkId < chunksCount; chunkId++)
    {
        if (aStopFlag.test() == true) [[unlikely]]
        {
            THROW_GP("Process was interrupted");
        }

        const size_t    dataLeftSize        = aData.Count();
        const size_t    dataToProcessSize   = std::min(maxChunkSize, dataLeftSize);
        GpSpanByteR     dataToProcessPtr    = aData.SubspanThenOffsetAdd(dataToProcessSize);

        THROW_COND_GP
        (
            crypto_hash_sha512_update
            (
                &state,
                dataToProcessPtr.PtrAs<const unsigned char*>(),
                dataToProcessPtr.Count()
            ) == 0,
            "`crypto_hash_sha512_update` returns error"_sv
        );

        dataProcessedSize += dataToProcessSize;

        if (aEventChannelOpt.has_value())
        {
            dataProcessUpdateEventEmitter.Update
            (
                dataProcessedSize,
                aEventChannelOpt.value().get()
            );
        }
    }

    THROW_COND_GP
    (
        crypto_hash_sha512_final(&state, aResOut.PtrAs<unsigned char*>()) == 0,
        "`crypto_hash_sha512_final` returns error"_sv
    );
}

GpCryptoHash_Sha2::Res512T  GpCryptoHash_Sha2::S_512
(
    GpSpanByteR                     aData,
    const size_t                    aMaxChunkSize,
    std::atomic_flag&               aStopFlag,
    GpEventChannelAny::C::Opt::Ref  aEventChannelOpt
)
{
    Res512T         res;
    GpSpanByteRW    r{res};

    S_512(aData, r, aMaxChunkSize, aStopFlag, aEventChannelOpt);

    return res;
}

}// namespace GPlatform
