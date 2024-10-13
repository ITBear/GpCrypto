#pragma once

#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoKeyPair
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoKeyPair)
    CLASS_DD(GpCryptoKeyPair)

protected:
                                GpCryptoKeyPair     (GpSecureStorage::CSP   aPrivateKey,
                                                     GpSpanByteR            aPublicKey);

public:
    virtual                     ~GpCryptoKeyPair    (void) noexcept;

    void                        Clear               (void) noexcept;

    const GpSecureStorage::CSP  PrivateKey          (void) const {return iPrivateKey;}
    const GpSpanByteR           PublicKey           (void) const noexcept {return iPublicKey;}

private:
    GpSecureStorage::CSP        iPrivateKey;
    GpBytesArray                iPublicKey;
};

}// namespace GPlatform
