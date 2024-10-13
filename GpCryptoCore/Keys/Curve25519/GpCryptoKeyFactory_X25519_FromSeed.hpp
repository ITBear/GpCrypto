#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoEncryptKeyFactory.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoKeyFactory_X25519_FromSeed final: public GpCryptoEncryptKeyFactory
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoKeyFactory_X25519_FromSeed)
    CLASS_DD(GpCryptoKeyFactory_X25519_FromSeed)

public:
                                        GpCryptoKeyFactory_X25519_FromSeed  (GpSecureStorage::CSP aSeed) noexcept;
    virtual                             ~GpCryptoKeyFactory_X25519_FromSeed (void) noexcept override final;

    virtual GpCryptoEncryptKeyPair::CSP Generate                            (void) override final;

private:
    GpSecureStorage::CSP                iSeed;
};

}// namespace GPlatform
