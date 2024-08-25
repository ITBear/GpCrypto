#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoKeyPair.hpp>

namespace GPlatform {

class GpCryptoKeyFactory
{
public:
    CLASS_REMOVE_CTRS_MOVE_COPY(GpCryptoKeyFactory)
    CLASS_DD(GpCryptoKeyFactory)

protected:
                                    GpCryptoKeyFactory  (void) noexcept {}

public:
    virtual                         ~GpCryptoKeyFactory (void) noexcept {}

    virtual GpCryptoKeyPair::CSP    Generate            (void) = 0;
    //virtual void                  Serialize           (GpByteWriter& aWriter) const = 0;
    //virtual void                  Deserialize         (GpByteReader& aReader) = 0;
};

}// namespace GPlatform
