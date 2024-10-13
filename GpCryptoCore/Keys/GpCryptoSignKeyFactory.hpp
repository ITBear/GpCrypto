#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoSignKeyPair.hpp>

namespace GPlatform {

class GpCryptoSignKeyFactory
{
public:
    CLASS_REMOVE_CTRS_MOVE_COPY(GpCryptoSignKeyFactory)
    CLASS_DD(GpCryptoSignKeyFactory)

protected:
                                        GpCryptoSignKeyFactory  (void) noexcept {}

public:
    virtual                             ~GpCryptoSignKeyFactory (void) noexcept {}

    virtual GpCryptoSignKeyPair::CSP    Generate                (void) = 0;
};

}// namespace GPlatform
