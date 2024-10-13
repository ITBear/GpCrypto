#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyFactory_X25519_FromSeed.hpp>
#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyPair_X25519.hpp>

#if defined(RELEASE_BUILD_STATIC)
#   define SODIUM_STATIC
#endif

//GP_WARNING_PUSH()
//GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

//GP_WARNING_POP()

namespace GPlatform {

GpCryptoKeyFactory_X25519_FromSeed::GpCryptoKeyFactory_X25519_FromSeed (GpSecureStorage::CSP aSeed) noexcept:
iSeed{std::move(aSeed)}
{
}

GpCryptoKeyFactory_X25519_FromSeed::~GpCryptoKeyFactory_X25519_FromSeed (void) noexcept
{
}

GpCryptoEncryptKeyPair::CSP GpCryptoKeyFactory_X25519_FromSeed::Generate (void)
{
    THROW_COND_GP
    (
        iSeed.V().Size() == size_t(crypto_box_curve25519xsalsa20poly1305_SEEDBYTES),
        "Wrong seed size"_sv
    );

    GpSecureStorage::SP privateBytes = MakeSP<GpSecureStorage>();
    GpBytesArray        publicBytes;

    privateBytes.V().Resize(size_t(crypto_box_SECRETKEYBYTES));
    publicBytes.resize(size_t(crypto_box_PUBLICKEYBYTES));

    GpSpanByteRW publicBytesPtr = GpSpanByteRW(publicBytes);

    const auto res = crypto_box_seed_keypair
    (
        publicBytesPtr.PtrAs<unsigned char*>(),
        privateBytes.V().ViewRW().RW().PtrAs<unsigned char*>(),
        iSeed.V().ViewR().R().PtrAs<const unsigned char*>()
    );

    if (res != 0)
    {
        THROW_GP("crypto_box_seed_keypair return error"_sv);
    }

    return MakeCSP<GpCryptoKeyPair_X25519>(privateBytes, std::move(publicBytes));
}

}// namespace GPlatform
