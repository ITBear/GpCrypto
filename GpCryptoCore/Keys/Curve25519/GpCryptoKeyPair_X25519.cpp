#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyPair_X25519.hpp>

GP_WARNING_PUSH()
GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

//const std::string_view    GpCryptoKeyPair_X25519::sPrivateBytesPrefix = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20"_sv;
//const std::string_view    GpCryptoKeyPair_X25519::sPublicBytesPrefix      = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"_sv;

/*GpCryptoKeyPair_X25519::GpCryptoKeyPair_X25519 (void) noexcept:
GpCryptoKeyPair(GpCryptoKeyType::X_25519)
{
}

GpCryptoKeyPair_X25519::GpCryptoKeyPair_X25519 (const GpCryptoKeyPair_X25519& aKeyPair):
GpCryptoKeyPair(aKeyPair)
{
}

GpCryptoKeyPair_X25519::GpCryptoKeyPair_X25519 (GpCryptoKeyPair_X25519&& aKeyPair):
GpCryptoKeyPair(std::move(aKeyPair))
{
}

GpCryptoKeyPair_X25519::GpCryptoKeyPair_X25519 (GpSecureStorage&&   aPrivateBytes,
                                                  GpBytesArray&&    aPublicBytes):
GpCryptoKeyPair(GpCryptoKeyType::X_25519,
                std::move(aPrivateBytes),
                std::move(aPublicBytes))
{
}

GpCryptoKeyPair_X25519::~GpCryptoKeyPair_X25519 (void) noexcept
{
}

GpSpanByteR GpCryptoKeyPair_X25519::PrivateBytesPrefix (void) const noexcept
{
    THROW_GP_NOT_IMPLEMENTED();
    //return sPrivateBytesPrefix;
}

GpSpanByteR GpCryptoKeyPair_X25519::PublicBytesPrefix (void) const noexcept
{
    THROW_GP_NOT_IMPLEMENTED();
    //return sPublicBytesPrefix;
}*/

}// namespace GPlatform
