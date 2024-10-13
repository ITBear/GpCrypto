#pragma once

#include <GpCrypto/GpCryptoCore/Keys/GpCryptoSignKeyPair.hpp>
#include <GpCrypto/GpCryptoCore/Keys/HD/GpCryptoHDSchemeType.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoHDKeyStorage
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHDKeyStorage)
    CLASS_DD(GpCryptoHDKeyStorage)

    using SchemeTypeT   = GpCryptoHDSchemeType;
    using SchemeTypeTE  = SchemeTypeT::EnumT;

public:
                                GpCryptoHDKeyStorage    (SchemeTypeTE           aSchemeType,
                                                         GpSecureStorage::CSP   aChainCode,
                                                         GpSecureStorage::CSP   aKeyData) noexcept;
                                ~GpCryptoHDKeyStorage   (void) noexcept;

    SchemeTypeTE                SchemeType              (void) const noexcept {return iSchemeType;}
    const GpSecureStorage::CSP  ChainCode               (void) const noexcept {return iChainCode;}
    const GpSecureStorage::CSP  KeyData                 (void) const noexcept {return iKeyData;}

private:
    const SchemeTypeTE          iSchemeType;
    GpSecureStorage::CSP        iChainCode;
    GpSecureStorage::CSP        iKeyData;
};

}// namespace GPlatform
