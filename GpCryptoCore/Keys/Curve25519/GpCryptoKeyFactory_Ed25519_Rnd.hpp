#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoSignKeyFactory.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoKeyFactory_Ed25519_Rnd final: public GpCryptoSignKeyFactory
{
public:
    CLASS_REMOVE_CTRS_MOVE_COPY(GpCryptoKeyFactory_Ed25519_Rnd)
    CLASS_DD(GpCryptoKeyFactory_Ed25519_Rnd)

public:
                                        GpCryptoKeyFactory_Ed25519_Rnd      (void) noexcept;
    virtual                             ~GpCryptoKeyFactory_Ed25519_Rnd (void) noexcept override final;

    virtual GpCryptoSignKeyPair::CSP    Generate                            (void) override final;
};

}// namespace GPlatform
