#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoSignKeyFactory.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoKeyFactory_Ed25519_FromSeed final: public GpCryptoSignKeyFactory
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoKeyFactory_Ed25519_FromSeed)
    CLASS_DD(GpCryptoKeyFactory_Ed25519_FromSeed)

public:
                                        GpCryptoKeyFactory_Ed25519_FromSeed     (GpSecureStorage::CSP aSeed) noexcept;
    virtual                             ~GpCryptoKeyFactory_Ed25519_FromSeed    (void) noexcept override final;

    virtual GpCryptoSignKeyPair::CSP    Generate                                (void) override final;

private:
    GpSecureStorage::CSP                iSeed;
};

}// namespace GPlatform
