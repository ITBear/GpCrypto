#pragma once

#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoRandom
{
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoRandom)

public:
    static void                 SEntropy    (size_t         aSize,
                                             GpSpanByteRW   aResOut);
    static GpSecureStorage::CSP SEntropy    (size_t aSize);
};

}// namespace GPlatform
