#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoKeyPair.hpp>

namespace GPlatform {

/*class GP_CRYPTO_CORE_API GpCryptoKeyPair_X25519 final : public GpCryptoKeyPair
{
public:
    CLASS_DD(GpCryptoKeyPair_X25519)

    using ResSignT = std::array<std::byte, 64>;

public:
                                GpCryptoKeyPair_X25519      (void) noexcept;
                                GpCryptoKeyPair_X25519      (const GpCryptoKeyPair_X25519& aKeyPair);
                                GpCryptoKeyPair_X25519      (GpCryptoKeyPair_X25519&& aKeyPair);
                                GpCryptoKeyPair_X25519      (GpSecureStorage&&  aPrivateBytes,
                                                             GpBytesArray&&     aPublicBytes);
    virtual                     ~GpCryptoKeyPair_X25519     (void) noexcept override final;

    virtual GpSpanByteR     PrivateBytesPrefix          (void) const noexcept override final;
    virtual GpSpanByteR     PublicBytesPrefix           (void) const noexcept override final;

    //static GpSpanByteR        SPrivateBytesPrefix         (void) noexcept {return sPrivateBytesPrefix;}
    //static GpSpanByteR        SPublicBytesPrefix          (void) noexcept {return sPublicBytesPrefix;}

private:
    //static const std::string_view sPrivateBytesPrefix;
    //static const std::string_view sPublicBytesPrefix;
};*/

}// namespace GPlatform
