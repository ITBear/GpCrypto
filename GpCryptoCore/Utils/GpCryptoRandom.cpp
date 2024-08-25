#include <GpCrypto/GpCryptoCore/Utils/GpCryptoRandom.hpp>
#include <GpCore2/GpUtils/Other/GpRAIIonDestruct.hpp>

GP_WARNING_PUSH()
GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

void    GpCryptoRandom::SEntropy
(
    const size_t    aSize,
    GpSpanByteRW    aResOut
)
{
    THROW_COND_GP
    (
        aResOut.Count() >= aSize,
        "Out of range"_sv
    );

    size_t      bytesLeft   = aSize;
    u_int_32    randVal     = 0;

    GpRAIIonDestruct randValDestructor([&]()
    {
        sodium_memzero(&randVal, sizeof(randVal));
    });

    while (bytesLeft > 0)
    {
        const size_t bytesNeed = std::min(sizeof(randVal), bytesLeft);

        randVal = randombytes_random();

        std::memcpy(aResOut.Ptr(), &randVal, bytesNeed);
        aResOut.OffsetAdd(bytesNeed);
        bytesLeft -= bytesNeed;
    }
}

GpSecureStorage::CSP    GpCryptoRandom::SEntropy (const size_t  aSize)
{
    GpSecureStorage::SP entropySP   = MakeSP<GpSecureStorage>();
    GpSecureStorage&    entropy     = entropySP.V();
    entropy.Resize(aSize);

    GpSecureStorageViewRW   entropyView = entropy.ViewRW();
    GpSpanByteRW            entropyData = entropyView.RW();

    SEntropy(aSize, entropyData);

    return entropySP;
}

}// namespace GPlatform
