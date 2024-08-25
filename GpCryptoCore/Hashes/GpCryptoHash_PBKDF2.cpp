#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_PBKDF2.hpp>
#include <GpCore2/GpUtils/Other/GpRAIIonDestruct.hpp>
#include <GpCore2/GpUtils/Types/Bits/GpBitOps.hpp>

GP_WARNING_PUSH()
GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

GpSecureStorage::CSP    GpCryptoHash_PBKDF2::S_HmacSHA512
(
    GpSpanByteR         aPassword,
    GpSpanByteR         aSalt,
    const size_t        aIterations,
    const size_bit_t    aBitLengthDerivedKey
)
{
    THROW_COND_GP
    (
        aPassword.Count() > 0,
        "Wrong password length"_sv
    );

    THROW_COND_GP
    (
        aSalt.Count() > 0,
        "Wrong salt length"_sv
    );

    THROW_COND_GP
    (
           (aBitLengthDerivedKey > 0_bit)
        && (aBitLengthDerivedKey % 8_bit == 0_bit)
        && (aBitLengthDerivedKey <= 0x1fffffffe0_bit),
        "Wrong aBitLengthDerivedKey length"_sv
    );

    const size_t    derivedKeySize      = size_byte_t(aBitLengthDerivedKey).As<size_t>();
    size_t          derivedKeyLeftBytes = derivedKeySize;

    GpSecureStorage::SP derivedKeySP    = MakeSP<GpSecureStorage>();
    GpSecureStorage&    derivedKey      = derivedKeySP.V();
    derivedKey.Resize(derivedKeySize);
    GpSecureStorageViewRW   derivedKeyViewRW    = derivedKey.ViewRW();
    GpSpanByteRW            derivedKeyPtrRW     = derivedKeyViewRW.RW();

    GpSecureStorage buf_U_T;
    constexpr const size_t sizeU    = size_t(crypto_auth_hmacsha512_BYTES);
    constexpr const size_t sizeT    = size_t(crypto_auth_hmacsha512_BYTES);
    buf_U_T.Resize(sizeU + sizeT);

    GpSecureStorageViewRW   buf_U_T_KeyViewRW   = buf_U_T.ViewRW();
    GpSpanByteRW            buf_U_T_KeyPtrRW    = buf_U_T_KeyViewRW.RW();
    GpSpanByteRW            dataU               = buf_U_T_KeyPtrRW.Subspan(0, sizeU);
    GpSpanByteRW            dataT               = buf_U_T_KeyPtrRW.Subspan(sizeU, sizeT);

    crypto_auth_hmacsha512_state pshCtx, hCtx;
    GpRAIIonDestruct hCtxDestructor([&]()
    {
        sodium_memzero(&pshCtx, sizeof(pshCtx));
        sodium_memzero(&hCtx, sizeof(hCtx));
    });

    crypto_auth_hmacsha512_init(&pshCtx, aPassword.PtrAs<const unsigned char*>(), aPassword.Count());
    crypto_auth_hmacsha512_update(&pshCtx, aSalt.PtrAs<const unsigned char*>(), aSalt.Count());

    size_t partsCount = (derivedKeySize / sizeT);
    if ((derivedKeySize % sizeT) > 0)
    {
        partsCount++;
    }

    for (size_t partId = 0; partId < partsCount; partId++)
    {
        u_int_32 ivecVal = NumOps::SConvert<u_int_32>(NumOps::SAdd(partId, size_t(1)));
        ivecVal = BitOps::H2N(ivecVal);

        MemOps::SCopy(hCtx, pshCtx);
        crypto_auth_hmacsha512_update(&hCtx, reinterpret_cast<const unsigned char*>(&ivecVal), sizeof(ivecVal));
        crypto_auth_hmacsha512_final(&hCtx, dataU.PtrAs<unsigned char*>());

        std::memcpy(dataT.Ptr(), dataU.Ptr(), dataU.Count());

        for (size_t j = 2; j <= aIterations; j++)
        {
            crypto_auth_hmacsha512_init(&hCtx, aPassword.PtrAs<const unsigned char*>(), aPassword.Count());
            crypto_auth_hmacsha512_update(&hCtx, dataU.PtrAs<const unsigned char*>(), sizeU);
            crypto_auth_hmacsha512_final(&hCtx, dataU.PtrAs<unsigned char*>());

            {
                u_int_8*        ptrT    = dataT.PtrAs<u_int_8*>();
                const u_int_8*  ptrU    = dataU.PtrAs<u_int_8*>();
                const size_t    count   = size_t(crypto_auth_hmacsha512_BYTES);

                for (size_t k = 0; k < count; k++)
                {
                    *ptrT++ ^= *ptrU++;
                }
            }
        }

        const size_t clen = std::min(derivedKeyLeftBytes, sizeT);

        derivedKeyPtrRW.CopyFrom(dataT.SubspanAs<GpSpanByteR>(0, clen));

        derivedKeyLeftBytes -= clen;
        derivedKeyPtrRW     += clen;
    }

    return derivedKeySP;
}

GpSecureStorage::CSP    GpCryptoHash_PBKDF2::S_HmacSHA256
(
    GpSpanByteR         aPassword,
    GpSpanByteR         aSalt,
    const size_t        aIterations,
    const size_bit_t    aBitLengthDerivedKey
)
{
    THROW_COND_GP
    (
        aPassword.Count() > 0,
        "Wrong password"_sv
    );

    THROW_COND_GP
    (
        aSalt.Count() > 0,
        "Wrong salt"_sv
    );

    THROW_COND_GP
    (
           (aBitLengthDerivedKey > 0_bit)
        && (aBitLengthDerivedKey % 8_bit == 0_bit)
        && (aBitLengthDerivedKey <= 0x1fffffffe0_bit),
        "Wrong aBitLengthDerivedKey"_sv
    );

    const size_t    derivedKeySize      = size_byte_t(aBitLengthDerivedKey).As<size_t>();
    size_t          derivedKeyLeftBytes = derivedKeySize;

    GpSecureStorage::SP derivedKeySP    = MakeSP<GpSecureStorage>();
    GpSecureStorage&    derivedKey      = derivedKeySP.V();
    derivedKey.Resize(derivedKeySize);
    GpSecureStorageViewRW   derivedKeyViewRW    = derivedKey.ViewRW();
    GpSpanByteRW            derivedKeyPtrRW     = derivedKeyViewRW.RW();

    GpSecureStorage buf_U_T;
    constexpr const size_t sizeU    = size_t(crypto_auth_hmacsha256_BYTES);
    constexpr const size_t sizeT    = size_t(crypto_auth_hmacsha256_BYTES);
    buf_U_T.Resize(sizeU + sizeT);
    GpSecureStorageViewRW   buf_U_T_KeyViewRW   = buf_U_T.ViewRW();
    GpSpanByteRW            buf_U_T_KeyPtrRW    = buf_U_T_KeyViewRW.RW();
    GpSpanByteRW            dataU               = buf_U_T_KeyPtrRW.Subspan(0, sizeU);
    GpSpanByteRW            dataT               = buf_U_T_KeyPtrRW.Subspan(sizeU, sizeT);

    crypto_auth_hmacsha256_state pshCtx, hCtx;
    GpRAIIonDestruct hCtxDestructor([&]()
    {
        sodium_memzero(&pshCtx, sizeof(pshCtx));
        sodium_memzero(&hCtx, sizeof(hCtx));
    });

    crypto_auth_hmacsha256_init(&pshCtx, aPassword.PtrAs<const unsigned char*>(), aPassword.Count());
    crypto_auth_hmacsha256_update(&pshCtx, aSalt.PtrAs<const unsigned char*>(), aSalt.Count());

    size_t partsCount = (derivedKeySize / sizeT);
    if ((derivedKeySize % sizeT) > 0)
    {
        partsCount++;
    }

    for (size_t partId = 0; partId < partsCount; partId++)
    {
        u_int_32 ivecVal = NumOps::SConvert<u_int_32>(NumOps::SAdd(partId, size_t(1)));
        ivecVal = BitOps::H2N(ivecVal);

        MemOps::SCopy(hCtx, pshCtx);
        crypto_auth_hmacsha256_update(&hCtx, reinterpret_cast<const unsigned char*>(&ivecVal), sizeof(ivecVal));
        crypto_auth_hmacsha256_final(&hCtx, dataU.PtrAs<unsigned char*>());

        dataT.CopyFrom(dataU);

        for (size_t j = 2; j <= aIterations; j++)
        {
            crypto_auth_hmacsha256_init(&hCtx, aPassword.PtrAs<const unsigned char*>(), aPassword.Count());
            crypto_auth_hmacsha256_update(&hCtx, dataU.PtrAs<const unsigned char*>(), sizeU);
            crypto_auth_hmacsha256_final(&hCtx, dataU.PtrAs<unsigned char*>());

            {
                u_int_8*        ptrT    = dataT.PtrAs<u_int_8*>();
                const u_int_8*  ptrU    = dataU.PtrAs<u_int_8*>();
                const size_t    count   = size_t(crypto_auth_hmacsha256_BYTES);

                for (size_t k = 0; k < count; k++)
                {
                    *ptrT++ ^= *ptrU++;
                }
            }
        }

        const size_t clen = std::min(derivedKeyLeftBytes, sizeT);
        derivedKeyPtrRW.CopyFrom(dataT.SubspanAs<GpSpanByteR>(0, clen));
        derivedKeyLeftBytes -= clen;
        derivedKeyPtrRW     += clen;
    }

    return derivedKeySP;
}

}// namespace GPlatform
