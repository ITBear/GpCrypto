#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoEncryptKeyPair.hpp>

namespace GPlatform {

class GpCryptoEncryptKeyFactory
{
public:
    CLASS_REMOVE_CTRS_MOVE_COPY(GpCryptoEncryptKeyFactory)
    CLASS_DD(GpCryptoEncryptKeyFactory)

protected:
                                            GpCryptoEncryptKeyFactory   (void) noexcept {}

public:
    virtual                                 ~GpCryptoEncryptKeyFactory  (void) noexcept {}

    virtual GpCryptoEncryptKeyPair::CSP     Generate                    (void) = 0;
};

}// namespace GPlatform
