#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoEncryptKeyPair.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoKeyPair_X25519 final : public GpCryptoEncryptKeyPair
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoKeyPair_X25519)
    CLASS_DD(GpCryptoKeyPair_X25519)

public:
                                GpCryptoKeyPair_X25519  (GpSecureStorage::CSP   aPrivateKey,
                                                         GpSpanByteR            aPublicKey) noexcept;
    virtual                     ~GpCryptoKeyPair_X25519 (void) noexcept override final;



};

}// namespace GPlatform
