#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorageViewRW.hpp>
#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>

namespace GPlatform {

GpSecureStorageViewRW::GpSecureStorageViewRW (GpSecureStorage& aStorage):
iStorage{aStorage}
{
    GpSecureStorage& storage = iStorage.value();

    storage.SetViewing(true);
    storage.UnlockRW();
}

GpSecureStorageViewRW::GpSecureStorageViewRW (GpSecureStorageViewRW&& aView) noexcept:
iStorage(std::move(aView.iStorage))
{
}

GpSecureStorageViewRW::~GpSecureStorageViewRW   (void) noexcept
{
    Release();
}

GpSecureStorageViewRW&  GpSecureStorageViewRW::operator= (GpSecureStorageViewRW&& aView)
{
    if (this == &aView)
    {
        return *this;
    }

    Release();
    iStorage = std::move(aView.iStorage);
    aView.iStorage.reset();

    return *this;
}

GpSpanByteR GpSecureStorageViewRW::R (void) const
{
    THROW_COND_GP
    (
        iStorage.has_value(),
        "Storage is null"_sv
    );

    const GpSecureStorage& storage = iStorage.value();
    return storage.DataR();
}

GpSpanByteRW    GpSecureStorageViewRW::RW (void)
{
    THROW_COND_GP
    (
        iStorage.has_value(),
        "Storage is null"_sv
    );

    GpSecureStorage& storage = iStorage.value();
    return storage.DataRW();
}

size_t  GpSecureStorageViewRW::Size (void) const noexcept
{
    if (iStorage.has_value() == false)
    {
        return 0;
    }

    GpSecureStorage& storage = iStorage.value();
    return storage.Size();
}

void    GpSecureStorageViewRW::Release (void)
{
    if (iStorage.has_value() == false)
    {
        return;
    }

    const GpSecureStorage& storage = iStorage.value();

    storage.LockRW();
    storage.SetViewing(false);
    iStorage.reset();
}

}// namespace GPlatform
