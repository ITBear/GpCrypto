#include <GpCrypto/GpCryptoCore/Keys/GpCryptoSignKeyPair.hpp>

namespace GPlatform {

GpCryptoSignKeyPair::GpCryptoSignKeyPair
(
    const TypeTE            aType,
    GpSecureStorage::CSP    aPrivateKey,
    GpSpanByteR             aPublicKey
):
GpCryptoKeyPair{std::move(aPrivateKey), aPublicKey},
iType{aType}
{
}

GpCryptoSignKeyPair::~GpCryptoSignKeyPair (void) noexcept
{
}

}// namespace GPlatform
