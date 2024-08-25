#pragma once

#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>
#include <GpCore2/GpUtils/EventBus/GpEventChannelAny.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoHash_Sha2
{
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHash_Sha2)

public:
    using Res256T = std::array<std::byte, 32>;
    using Res512T = std::array<std::byte, 64>;

public:
    static Res256T      S_256   (GpSpanByteR                    aData);

    static void         S_256   (GpSpanByteR                    aData,
                                 GpSpanByteRW                   aResOut,
                                 size_t                         aMaxChunkSize,
                                 std::atomic_flag&              aStopFlag,
                                 GpEventChannelAny::C::Opt::Ref aEventChannelOpt);
    static Res256T      S_256   (GpSpanByteR                    aData,
                                 size_t                         aMaxChunkSize,
                                 std::atomic_flag&              aStopFlag,
                                 GpEventChannelAny::C::Opt::Ref aEventChannelOpt);

    static void         S_512   (GpSpanByteR                    aData,
                                 GpSpanByteRW                   aResOut,
                                 size_t                         aMaxChunkSize,
                                 std::atomic_flag&              aStopFlag,
                                 GpEventChannelAny::C::Opt::Ref aEventChannelOpt);
    static Res512T      S_512   (GpSpanByteR                    aData,
                                 size_t                         aMaxChunkSize,
                                 std::atomic_flag&              aStopFlag,
                                 GpEventChannelAny::C::Opt::Ref aEventChannelOpt);
};

}// namespace GPlatform
