#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoHDKeyGen_Ed25519.hpp>
#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Hmac.hpp>
#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Ripemd160.hpp>
#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyPair_Ed25519.hpp>
#include <GpCore2/GpUtils/Types/Units/Other/size_byte_t.hpp>
#include <GpCore2/GpUtils/Streams/GpByteWriter.hpp>
#include <GpCore2/GpUtils/Streams/GpByteWriterStorageFixedSize.hpp>

namespace GPlatform {

GpCryptoHDKeyStorage::SP    GpCryptoHDKeyGen_Ed25519::SMasterKeyPairFromSeed (GpSpanByteR aSeed)
{
    GpSecureStorage valI;
    valI.Resize((512_bit).As<size_byte_t>().As<size_t>());

    GpCryptoHash_Hmac::S_512
    (
        aSeed,
        "ed25519 seed"_sv,
        valI.ViewRW().RW()
    );

    GpSecureStorageViewR    valIViewR   = valI.ViewR();
    GpSpanByteR             valIViewPtr = valIViewR.R();
    GpSpanByteR             valIL       = valIViewPtr.Subspan(0, 32);
    GpSpanByteR             valIR       = valIViewPtr.Subspan(32, 32);

    GpSecureStorage::SP chainCode   = MakeSP<GpSecureStorage>();
    GpSecureStorage::SP privateData = MakeSP<GpSecureStorage>();

    chainCode.V().CopyFrom(valIR);
    privateData.V().CopyFrom(valIL);

    return MakeSP<GpCryptoHDKeyStorage>
    (
        GpCryptoHDSchemeType::SLIP10_ED25519,
        std::move(chainCode),
        std::move(privateData)
    );
}

GpCryptoHDKeyStorage::SP    GpCryptoHDKeyGen_Ed25519::SChildKeyPair
(
    const GpCryptoHDKeyStorage& aParentHDKeyStorage,
    const size_t                aChildId
)
{
    THROW_COND_GP
    (
        aParentHDKeyStorage.SchemeType() == GpCryptoHDSchemeType::SLIP10_ED25519,
        "HD scheme type must be SLIP10_ED25519"_sv
    );

    //SLIP10_ED25519 only supports hardened keys
    const size_t childCode = aChildId + size_t(0x80000000);

    GpSecureStorage sourceData;

    //Always hardened
    {
        sourceData.Resize(1 + 32 + 4);
        GpSecureStorageViewRW           sourceDataViewRW = sourceData.ViewRW();
        GpByteWriterStorageFixedSize    sourceDataStorage(sourceDataViewRW.RW());
        GpByteWriter                    sourceDataWriter(sourceDataStorage);

        sourceDataWriter.UI8(0);
        sourceDataWriter.Bytes(aParentHDKeyStorage.KeyData().V().ViewR().R());
        sourceDataWriter.UI32(NumOps::SConvert<u_int_32>(childCode));
    }

    GpSecureStorage valI;
    valI.Resize((512_bit).As<size_byte_t>().As<size_t>());

    GpCryptoHash_Hmac::S_512
    (
        sourceData.ViewR().R(),
        aParentHDKeyStorage.ChainCode().V().ViewR().R(),
        valI.ViewRW().RW()
    );

    GpSecureStorageViewR    valIViewR   = valI.ViewR();
    GpSpanByteR             valIViewPtr = valIViewR.R();
    GpSpanByteR             valIL       = valIViewPtr.Subspan(0, 32);
    GpSpanByteR             valIR       = valIViewPtr.Subspan(32, 32);

    GpSecureStorage::SP chainCode   = MakeSP<GpSecureStorage>();
    GpSecureStorage::SP privateData = MakeSP<GpSecureStorage>();

    chainCode.V().CopyFrom(valIR);
    privateData.V().CopyFrom(valIL);

    return MakeSP<GpCryptoHDKeyStorage>
    (
        GpCryptoHDSchemeType::SLIP10_ED25519,
        std::move(chainCode),
        std::move(privateData)
    );
}

}// namespace GPlatform
