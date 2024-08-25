#pragma once

#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoHash_Ripemd160
{
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHash_Ripemd160)

public:
    using Res160T = std::array<std::byte, 20>;

public:
    static void         S_H (GpSpanByteR    aData,
                             GpSpanByteRW   aResOut);

    static Res160T      S_H (GpSpanByteR aData);
};

}// namespace GPlatform
