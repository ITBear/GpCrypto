#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoSignKeyPair.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoKeyPair_Ed25519 final : public GpCryptoSignKeyPair
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoKeyPair_Ed25519)
    CLASS_DD(GpCryptoKeyPair_Ed25519)

public:
                                GpCryptoKeyPair_Ed25519     (GpSecureStorage::CSP   aPrivateKey,
                                                             GpSpanByteR            aPublicKey) noexcept;
    virtual                     ~GpCryptoKeyPair_Ed25519    (void) noexcept override final;

    virtual GpBytesArray        Sign                        (GpSpanByteR aData) const override final;
    [[nodiscard]] virtual bool  VerifySign                  (GpSpanByteR aData,
                                                             GpSpanByteR aSign) const override final;

    static GpBytesArray         SSign                       (GpSpanByteR aData,
                                                             GpSpanByteR aPrivateKey);
    static bool                 SVerifySign                 (GpSpanByteR aData,
                                                             GpSpanByteR aSign,
                                                             GpSpanByteR aPublicKey);
};

}// namespace GPlatform
