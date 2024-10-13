#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoSignKeyType.hpp>
#include <GpCrypto/GpCryptoCore/Keys/GpCryptoKeyPair.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoSignKeyPair: public GpCryptoKeyPair
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoSignKeyPair)
    CLASS_DD(GpCryptoSignKeyPair)

    using TypeT     = GpCryptoSignKeyType;
    using TypeTE    = TypeT::EnumT;

protected:
                                GpCryptoSignKeyPair     (TypeTE                 aType,
                                                         GpSecureStorage::CSP   aPrivateKey,
                                                         GpSpanByteR            aPublicKey);

public:
    virtual                     ~GpCryptoSignKeyPair    (void) noexcept;

    TypeTE                      Type                    (void) const noexcept {return iType;}

    virtual GpBytesArray        Sign                    (GpSpanByteR aData) const = 0;
    [[nodiscard]] virtual bool  VerifySign              (GpSpanByteR aData,
                                                         GpSpanByteR aSign) const = 0;

private:
    const TypeTE                iType;
};

}// namespace GPlatform
