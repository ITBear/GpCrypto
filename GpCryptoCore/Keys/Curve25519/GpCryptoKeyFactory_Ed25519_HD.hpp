#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoSignKeyFactory.hpp>
#include <GpCrypto/GpCryptoCore/Keys/HD/GpCryptoHDKeyStorage.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoKeyFactory_Ed25519_HD final: public GpCryptoSignKeyFactory
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoKeyFactory_Ed25519_HD)
    CLASS_DD(GpCryptoKeyFactory_Ed25519_HD)

public:
                                        GpCryptoKeyFactory_Ed25519_HD   (GpCryptoHDKeyStorage::CSP aParentHDKeyStorage) noexcept;
    virtual                             ~GpCryptoKeyFactory_Ed25519_HD  (void) noexcept override final;

    virtual GpCryptoSignKeyPair::CSP    Generate                        (void) override final;

private:
    GpCryptoHDKeyStorage::CSP           iParentHDKeyStorage;
    size_t                              iChildNumber        = 0;
};

}// namespace GPlatform
