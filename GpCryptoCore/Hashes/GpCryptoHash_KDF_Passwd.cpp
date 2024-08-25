#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_KDF_Passwd.hpp>

GP_WARNING_PUSH()
GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

GpSecureStorage::CSP    GpCryptoHash_KDF_Passwd::S_H
(
    GpSpanByteR         aPassword,
    GpSpanByteR         aSalt,
    const size_bit_t    aBitLengthDerivedKey,
    const size_mibyte_t aMemoryLimit
)
{
#if (crypto_pwhash_PASSWD_MIN > 0)
    THROW_COND_GP
    (
           (aPassword.Count() >= size_t(crypto_pwhash_PASSWD_MIN))
        && (aPassword.Count() <= size_t(crypto_pwhash_PASSWD_MAX)),
        "Wrong password length"_sv
    );
#else
    THROW_COND_GP
    (
        (aPassword.Count() <= size_t(crypto_pwhash_PASSWD_MAX)),
        "Wrong password length"_sv
    );
#endif

    THROW_COND_GP
    (
        aSalt.Count() == size_t(crypto_pwhash_SALTBYTES),
        "Wrong salt length (must be 16 bytes)"_sv
    );

GP_WARNING_PUSH()
GP_WARNING_DISABLE_GCC(duplicated-branches)

    THROW_COND_GP
    (
           (aBitLengthDerivedKey >= size_byte_t::SMake(crypto_pwhash_BYTES_MIN))
        && (aBitLengthDerivedKey <= size_byte_t::SMake(crypto_pwhash_BYTES_MAX))
        && (aBitLengthDerivedKey % 8_bit == 0_bit),
        "Wrong aBitLengthDerivedKey length"_sv
    );

GP_WARNING_POP()

    const size_t derivedKeySize = size_byte_t(aBitLengthDerivedKey).As<size_t>();

    GpSecureStorage::SP derivedKeySP    = MakeSP<GpSecureStorage>();
    GpSecureStorage&    derivedKey      = derivedKeySP.V();
    derivedKey.Resize(derivedKeySize);

    const auto crypto_pwhash_res = crypto_pwhash
    (
        derivedKey.ViewRW().RW().PtrAs<unsigned char*>(),
        derivedKeySize,
        aPassword.PtrAs<const char*>(),
        aPassword.Count(),
        aSalt.PtrAs<const unsigned char*>(),
        3,//crypto_pwhash_OPSLIMIT_INTERACTIVE,
        aMemoryLimit.As<size_t>(),//crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT
    );

    THROW_COND_GP
    (
        crypto_pwhash_res == 0,
        "crypto_pwhash return error"_sv
    );

    return derivedKeySP;
}

}// namespace
