#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoKeyFactory.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoKeyFactory_Ed25519_Rnd final: public GpCryptoKeyFactory
{
public:
    CLASS_REMOVE_CTRS_MOVE_COPY(GpCryptoKeyFactory_Ed25519_Rnd)
    CLASS_DD(GpCryptoKeyFactory_Ed25519_Rnd)

public:
                                    GpCryptoKeyFactory_Ed25519_Rnd  (void) noexcept;
    virtual                         ~GpCryptoKeyFactory_Ed25519_Rnd (void) noexcept override final;

    virtual GpCryptoKeyPair::CSP    Generate                        (void) override final;
    //virtual void                  Serialize                       (GpByteWriter& aWriter) const override final;
    //virtual void                  Deserialize                     (GpByteReader& aReader) override final;
};

}// namespace GPlatform
