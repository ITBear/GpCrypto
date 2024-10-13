#include <GpCrypto/GpCryptoCore/Keys/GpCryptoEncryptKeyPair.hpp>

namespace GPlatform {

GpCryptoEncryptKeyPair::GpCryptoEncryptKeyPair
(
    const TypeTE            aType,
    GpSecureStorage::CSP    aPrivateKey,
    GpSpanByteR             aPublicKey
):
GpCryptoKeyPair{std::move(aPrivateKey), aPublicKey},
iType{aType}
{
}

GpCryptoEncryptKeyPair::~GpCryptoEncryptKeyPair (void) noexcept
{
}

}// namespace GPlatform
