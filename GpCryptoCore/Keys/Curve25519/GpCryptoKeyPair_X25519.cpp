#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyPair_X25519.hpp>

#if defined(RELEASE_BUILD_STATIC)
#   define SODIUM_STATIC
#endif

//GP_WARNING_PUSH()
//GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

//GP_WARNING_POP()

namespace GPlatform {

GpCryptoKeyPair_X25519::GpCryptoKeyPair_X25519
(
    GpSecureStorage::CSP    aPrivateKey,
    GpSpanByteR             aPublicKey
) noexcept:
GpCryptoEncryptKeyPair
{
    GpCryptoEncryptKeyType::X_25519,
    std::move(aPrivateKey),
    std::move(aPublicKey)
}
{
}

GpCryptoKeyPair_X25519::~GpCryptoKeyPair_X25519 (void) noexcept
{
}

}// namespace GPlatform
