#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoKeyType.hpp>
#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoKeyPair
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoKeyPair)
    CLASS_DD(GpCryptoKeyPair)

    using TypeT     = GpCryptoKeyType;
    using TypeTE    = TypeT::EnumT;

protected:
                                GpCryptoKeyPair     (TypeTE                 aType,
                                                     GpSecureStorage::CSP   aPrivateKey,
                                                     GpBytesArray&&         aPublicKey) noexcept;

public:
    virtual                     ~GpCryptoKeyPair    (void) noexcept;

    void                        Clear               (void) noexcept;

    TypeTE                      Type                (void) const noexcept {return iType;}

    const GpSecureStorage::CSP  PrivateKey          (void) const {return iPrivateKey;}
    const GpSpanByteR           PublicKey           (void) const noexcept {return GpSpanByteR(iPublicKey);}

    virtual GpSpanByteR         PrivateKeyPrefix    (void) const noexcept = 0;
    virtual GpSpanByteR         PublicKeyPrefix     (void) const noexcept = 0;

    virtual GpBytesArray        Sign                (GpSpanByteR    aData) const = 0;
    virtual bool                VerifySign          (GpSpanByteR    aData,
                                                     GpSpanByteR    aSign) const = 0;
protected:
    const TypeTE                iType;
    GpSecureStorage::CSP        iPrivateKey;
    GpBytesArray                iPublicKey;
};

}// namespace GPlatform
