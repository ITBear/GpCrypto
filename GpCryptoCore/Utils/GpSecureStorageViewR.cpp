#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorageViewR.hpp>
#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>

namespace GPlatform {

GpSecureStorageViewR::GpSecureStorageViewR (const GpSecureStorage& aStorage):
iStorage{aStorage}
{
    const GpSecureStorage& storage = iStorage.value();

    storage.SetViewing(true);
    storage.UnlockR();
}

GpSecureStorageViewR::GpSecureStorageViewR (GpSecureStorageViewR&& aView) noexcept:
iStorage{std::move(aView.iStorage)}
{
}

GpSecureStorageViewR::~GpSecureStorageViewR (void) noexcept
{
    Release();
}

GpSecureStorageViewR&   GpSecureStorageViewR::operator= (GpSecureStorageViewR&& aView)
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

GpSpanByteR GpSecureStorageViewR::R (void) const
{
    THROW_COND_GP
    (
        iStorage.has_value(),
        "Storage is null"_sv
    );

    const GpSecureStorage& storage = iStorage.value();
    return storage.DataR();
}

size_t  GpSecureStorageViewR::Size (void) const noexcept
{
    if (iStorage.has_value() == false)
    {
        return 0;
    }

    const GpSecureStorage& storage = iStorage.value();
    return storage.Size();
}

void    GpSecureStorageViewR::Release (void)
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
