#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoKeyPair.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoKeyPair_Ed25519 final : public GpCryptoKeyPair
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoKeyPair_Ed25519)
    CLASS_DD(GpCryptoKeyPair_Ed25519)

public:
                            GpCryptoKeyPair_Ed25519     (GpSecureStorage::CSP   aPrivateKey,
                                                         GpBytesArray&&         aPublicKey) noexcept;
    virtual                 ~GpCryptoKeyPair_Ed25519    (void) noexcept override final;

    virtual GpBytesArray    Sign                        (GpSpanByteR    aData) const override final;
    virtual bool            VerifySign                  (GpSpanByteR    aData,
                                                         GpSpanByteR    aSign) const override final;

    static GpBytesArray     SSign                       (GpSpanByteR            aData,
                                                         const GpSecureStorage& aPrivateKey);

    static bool             SVerifySign                 (GpSpanByteR    aData,
                                                         GpSpanByteR    aSign,
                                                         GpSpanByteR    aPublicKey);

    virtual GpSpanByteR     PrivateKeyPrefix            (void) const noexcept override final;
    virtual GpSpanByteR     PublicKeyPrefix             (void) const noexcept override final;

    static GpSpanByteR      SPrivateKeyPrefix           (void) noexcept {return sPrivateKeyPrefix;}
    static GpSpanByteR      SPublicKeyPrefix            (void) noexcept {return sPublicKeyPrefix;}

private:
    static const std::string_view   sPrivateKeyPrefix;
    static const std::string_view   sPublicKeyPrefix;
};

}// namespace GPlatform
