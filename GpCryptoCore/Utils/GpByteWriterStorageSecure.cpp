#include <GpCrypto/GpCryptoCore/Utils/GpByteWriterStorageSecure.hpp>

namespace GPlatform {

GpByteWriterStorageSecure::~GpByteWriterStorageSecure (void) noexcept
{
}

void    GpByteWriterStorageSecure::AllocateAdd
(
    const size_t    aSizeToAdd,
    GpSpanByteRW&   aStoragePtr
)
{
    const size_t usedSize       = size_t(aStoragePtr.Ptr() - iViewRW.R().Ptr());
    const size_t freeSize       = aStoragePtr.Count();
    const size_t newFreeSize    = NumOps::SAdd(freeSize, aSizeToAdd);
    const size_t newStorageSize = NumOps::SAdd(usedSize, newFreeSize);

    if (newStorageSize > iViewRW.R().Count())
    {
        iViewRW.Release();
        iStorage.Resize(newStorageSize);
        iViewRW = iStorage.ViewRW();
    }

    aStoragePtr.Set(iViewRW.RW().Ptr() + usedSize, newFreeSize);
}

void    GpByteWriterStorageSecure::_OnEnd (void)
{
    iViewRW.Release();
    iStorage.Resize(TotalWrite());
    iViewRW = iStorage.ViewRW();
}

}// namespace GPlatform
