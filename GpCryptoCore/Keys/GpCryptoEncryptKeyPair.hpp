#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoEncryptKeyType.hpp>
#include <GpCrypto/GpCryptoCore/Keys/GpCryptoKeyPair.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoEncryptKeyPair: public GpCryptoKeyPair
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoEncryptKeyPair)
    CLASS_DD(GpCryptoEncryptKeyPair)

    using TypeT     = GpCryptoEncryptKeyType;
    using TypeTE    = TypeT::EnumT;

protected:
                                GpCryptoEncryptKeyPair  (TypeTE                 aType,
                                                         GpSecureStorage::CSP   aPrivateKey,
                                                         GpSpanByteR            aPublicKey);

public:
    virtual                     ~GpCryptoEncryptKeyPair (void) noexcept;

    TypeTE                      Type                    (void) const noexcept {return iType;}

private:
    const TypeTE                iType;
};

}// namespace GPlatform
