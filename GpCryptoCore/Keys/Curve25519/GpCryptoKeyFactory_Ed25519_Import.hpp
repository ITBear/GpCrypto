#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoKeyFactory.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoKeyFactory_Ed25519_Import final: public GpCryptoKeyFactory
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoKeyFactory_Ed25519_Import)
    CLASS_DD(GpCryptoKeyFactory_Ed25519_Import)

public:
                                    GpCryptoKeyFactory_Ed25519_Import   (GpSecureStorage::CSP aSeed) noexcept;
    virtual                         ~GpCryptoKeyFactory_Ed25519_Import  (void) noexcept override final;

    virtual GpCryptoKeyPair::CSP    Generate                            (void) override final;
    //virtual void                  Serialize                           (GpByteWriter& aWriter) const override final;
    //virtual void                  Deserialize                         (GpByteReader& aReader) override final;

private:
    GpSecureStorage::CSP            iSeed;
};

}// namespace GPlatform
