#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoEncryptKeyFactory.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoKeyFactory_X25519_Rnd final: public GpCryptoEncryptKeyFactory
{
public:
    CLASS_REMOVE_CTRS_MOVE_COPY(GpCryptoKeyFactory_X25519_Rnd)
    CLASS_DD(GpCryptoKeyFactory_X25519_Rnd)

public:
                                        GpCryptoKeyFactory_X25519_Rnd   (void) noexcept;
    virtual                             ~GpCryptoKeyFactory_X25519_Rnd  (void) noexcept override final;

    virtual GpCryptoEncryptKeyPair::CSP Generate                        (void) override final;
};

}// namespace GPlatform
