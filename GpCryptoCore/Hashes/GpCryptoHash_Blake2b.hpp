#pragma once

#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoHash_Blake2b
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHash_Blake2b)

public:
    using Res256T = std::array<std::byte, 32>;

public:
    static void         S_256   (GpSpanByteR                aData,
                                 std::optional<GpSpanByteR> aKey,
                                 GpSpanByteRW               aResOut);

    static Res256T      S_256   (GpSpanByteR                aData,
                                 std::optional<GpSpanByteR> aKey = std::nullopt);
};

}// namespace GPlatform
