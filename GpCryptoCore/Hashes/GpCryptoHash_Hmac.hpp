#pragma once

#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoHash_Hmac
{
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHash_Hmac)

public:
    using Res256T = std::array<std::byte, 32>;
    using Res512T = std::array<std::byte, 64>;

public:
    static void         S_256   (GpSpanByteR    aData,
                                 GpSpanByteR    aKey,
                                 GpSpanByteRW   aResOut);

    static Res256T      S_256   (GpSpanByteR    aData,
                                 GpSpanByteR    aKey);

    static void         S_512   (GpSpanByteR    aData,
                                 GpSpanByteR    aKey,
                                 GpSpanByteRW   aResOut);

    static Res512T      S_512   (GpSpanByteR    aData,
                                 GpSpanByteR    aKey);
};

}// namespace GPlatform
