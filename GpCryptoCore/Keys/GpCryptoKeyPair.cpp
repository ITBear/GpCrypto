#include <GpCrypto/GpCryptoCore/Keys/GpCryptoKeyPair.hpp>

namespace GPlatform {

GpCryptoKeyPair::GpCryptoKeyPair
(
    GpSecureStorage::CSP    aPrivateKey,
    GpSpanByteR             aPublicKey
):
iPrivateKey{std::move(aPrivateKey)},
iPublicKey {GpBytesArrayUtils::SMake<GpBytesArray, GpSpanByteR>(aPublicKey)}
{
}

GpCryptoKeyPair::~GpCryptoKeyPair (void) noexcept
{
    Clear();
}

void    GpCryptoKeyPair::Clear (void) noexcept
{
    iPublicKey.clear();
    iPrivateKey.Clear();
}

/*GpSecureStorage::SP   GpCryptoKeyPair::ToPrivateBytesWithPrefix (void) const
{
    const GpSecureStorage& privateBytes = PrivateBytes();

    THROW_COND_GP
    (
        !privateBytes.Empty(),
        "Keypair is empty"_sv
    );

    GpSpanByteR                 prefixPtr   = PrivateBytesPrefix();
    GpSecureStorageViewR            privateView = privateBytes.ViewR();
    GpSpanByteR                 privatePtr  = privateView.R().Subrange(0_cnt, 32_cnt);

    const size_byte_t               resSize     = prefixPtr.SizeLeft() + privatePtr.SizeLeft();
    GpSecureStorage::SP             resSP       = MakeSP<GpSecureStorage>();
    GpSecureStorage&                res         = resSP.V();
    res.Resize(resSize);
    GpSecureStorageViewRW           resView     = res.ViewRW();
    GpByteWriterStorageFixedSize    resStorage(resView.RW());
    GpByteWriter                    resWriter(resStorage);

    resWriter.Bytes(prefixPtr);
    resWriter.Bytes(privatePtr);

    ???
    resWriter.OnShrinkToFit()
    ???

    return resSP;
}

GpSecureStorage::SP GpCryptoKeyPair::ToPrivateStrHexWithPrefix (void) const
{
    GpSecureStorage::SP     privateData = ToPrivateBytesWithPrefix();
    GpSecureStorageViewR    privateView = privateData->ViewR();
    GpSpanByteR         privatePtr  = privateView.R();

    //Str hex data
    const size_byte_t       resSize = privatePtr.SizeLeft() * 2_byte;
    GpSecureStorage::SP     resSP   = MakeSP<GpSecureStorage>();
    GpSecureStorage&        res     = resSP.V();
    res.Resize(resSize);

    StrOps::SFromBytesHex(privatePtr, res.ViewRW().RW());

    return resSP;
}

GpBytesArray    GpCryptoKeyPair::ToPublicBytesWithPrefix (void) const
{
    THROW_COND_GP
    (
        !iPublicBytes.empty(),
        "Keypair is empty"_sv
    );

    GpSpanByteR                 prefixPtr   = PublicBytesPrefix();

    const size_byte_t               resSize     = prefixPtr.SizeLeft() + size_byte_t::SMake(std::size(iPublicBytes));
    GpBytesArray                    res;
    res.resize(resSize.As<size_t>());
    GpByteWriterStorageFixedSize    resStorage(res);
    GpByteWriter                    resWriter(resStorage);

    resWriter.Bytes(prefixPtr);
    resWriter.Bytes(iPublicBytes);

    ???
    resWriter.OnShrinkToFit()
    ???

    return res;
}

GpBytesArray    GpCryptoKeyPair::ToPublicStrHexWithPrefix (void) const
{
    const GpBytesArray      publicData = ToPublicBytesWithPrefix();

    //Str hex data
    const size_byte_t       resSize = size_byte_t::SMake(std::size(publicData)) * 2_byte;
    GpBytesArray            res;
    res.resize(resSize.As<size_t>());

    StrOps::SFromBytesHex(publicData, res);

    return res;
}*/

}// namespace GPlatform
