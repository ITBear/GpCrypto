#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Hmac.hpp>
#include <GpCore2/GpUtils/Other/GpRAIIonDestruct.hpp>

#if defined(RELEASE_BUILD_STATIC)
#   define SODIUM_STATIC
#endif

//GP_WARNING_PUSH()
//GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

//GP_WARNING_POP()

namespace GPlatform {

void    GpCryptoHash_Hmac::S_256
(
    GpSpanByteR     aData,
    GpSpanByteR     aKey,
    GpSpanByteRW    aResOut
)
{
    THROW_COND_GP
    (

        aResOut.Count() >= std::tuple_size<Res256T>::value,
        "aRes size too small"_sv
    );

    crypto_auth_hmacsha256_state hCtx;
    GpRAIIonDestruct hCtxDestructor
    (
        [&]()
        {
            sodium_memzero(&hCtx, sizeof(hCtx));
        }
    );

    crypto_auth_hmacsha256_init
    (
        &hCtx,
        aKey.PtrAs<const unsigned char*>(),
        aKey.Count()
    );

    crypto_auth_hmacsha256_update
    (
        &hCtx,
        aData.PtrAs<const unsigned char*>(),
        aData.Count()
    );

    crypto_auth_hmacsha256_final
    (
        &hCtx,
        aResOut.PtrAs<unsigned char*>()
    );
}

GpCryptoHash_Hmac::Res256T  GpCryptoHash_Hmac::S_256
(
    GpSpanByteR aData,
    GpSpanByteR aKey
)
{
    Res256T res;
    GpSpanByteRW r(res);
    S_256(aData, aKey, r);
    return res;
}

void    GpCryptoHash_Hmac::S_512
(
    GpSpanByteR aData,
    GpSpanByteR aKey,
    GpSpanByteRW    aResOut
)
{
    THROW_COND_GP
    (
        aResOut.Count() >= std::tuple_size<Res512T>::value,
        "aRes size too small"_sv
    );

    crypto_auth_hmacsha512_state hCtx;
    GpRAIIonDestruct hCtxDestructor([&]()
    {
        sodium_memzero(&hCtx, sizeof(hCtx));
    });

    crypto_auth_hmacsha512_init
    (
        &hCtx,
        aKey.PtrAs<const unsigned char*>(),
        aKey.Count()
    );

    crypto_auth_hmacsha512_update
    (
        &hCtx,
        aData.PtrAs<const unsigned char*>(),
        aData.Count()
    );

    crypto_auth_hmacsha512_final
    (
        &hCtx,
        aResOut.PtrAs<unsigned char*>()
    );
}

GpCryptoHash_Hmac::Res512T  GpCryptoHash_Hmac::S_512
(
    GpSpanByteR aData,
    GpSpanByteR aKey
)
{
    Res512T res;
    GpSpanByteRW r(res);
    S_512(aData, aKey, r);
    return res;
}

}// namespace GPlatform
