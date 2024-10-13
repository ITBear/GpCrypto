#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyFactory_X25519_Rnd.hpp>
#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyPair_X25519.hpp>

#if defined(RELEASE_BUILD_STATIC)
#   define SODIUM_STATIC
#endif

//GP_WARNING_PUSH()
//GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

//GP_WARNING_POP()

namespace GPlatform {

GpCryptoKeyFactory_X25519_Rnd::GpCryptoKeyFactory_X25519_Rnd (void) noexcept
{
}

GpCryptoKeyFactory_X25519_Rnd::~GpCryptoKeyFactory_X25519_Rnd (void) noexcept
{
}

GpCryptoEncryptKeyPair::CSP GpCryptoKeyFactory_X25519_Rnd::Generate (void)
{
    GpSecureStorage::SP privateBytes = MakeSP<GpSecureStorage>();
    GpBytesArray        publicBytes;

    {
        privateBytes.V().Resize(size_t(crypto_box_SECRETKEYBYTES));
        publicBytes.resize(size_t(crypto_box_PUBLICKEYBYTES));

        GpSecureStorageViewRW   privateBytesView    = privateBytes.V().ViewRW();
        GpSpanByteRW            privateBytesPtr     = privateBytesView.RW();
        GpSpanByteRW            publicBytesPtr      = GpSpanByteRW(publicBytes);

        const auto res = crypto_box_keypair
        (
            publicBytesPtr.PtrAs<unsigned char*>(),
            privateBytesPtr.PtrAs<unsigned char*>()
        );

        if (res != 0)
        {
            THROW_GP("crypto_box_keypair return error"_sv);
        }
    }

    return MakeSP<GpCryptoKeyPair_X25519>(privateBytes, std::move(publicBytes));
}

}// namespace GPlatform
