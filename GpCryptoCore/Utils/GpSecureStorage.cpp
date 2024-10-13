#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>

#if defined(RELEASE_BUILD_STATIC)
#   define SODIUM_STATIC
#endif

//GP_WARNING_PUSH()
//GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

//GP_WARNING_POP()

#include <cstdlib>

// TODO: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! DEBUG, crash sodium_allocarray (remove after debug) !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#define OS_BROWSER
// TODO: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! DEBUG, crash sodium_allocarray (remove after debug) !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

namespace GPlatform {

GpSecureStorage::GpSecureStorage (void) noexcept
{
}

GpSecureStorage::~GpSecureStorage (void) noexcept
{
    Clear();
}

void    GpSecureStorage::Clear (void)
{
    THROW_COND_GP(IsViewing() == false, "Storage is viewing"_sv);

    if (iData != nullptr)
    {
        sodium_memzero(ViewRW().RW().Ptr(), iSizeAllocated);

#if !defined(OS_BROWSER)
        sodium_free(iData);
#else
        std::free(iData);
#endif
    }

    iData           = nullptr;
    iSizeUsed       = 0;
    iSizeAllocated  = 0;
    iAlignment      = 1;
    //iIsViewing    = false;//THROW_COND_GP(IsViewing() == false, "Storage is viewing"_sv);
}

void    GpSecureStorage::Resize (const size_t aSize)
{
    Resize(aSize, iAlignment);
}

void    GpSecureStorage::Resize
(
    const size_t aSize,
    const size_t aAlignment
)
{
    Reserve(aSize, aAlignment);
    iSizeUsed = aSize;
}

void    GpSecureStorage::Reserve (const size_t aSize)
{
    Reserve(aSize, iAlignment);
}

void    GpSecureStorage::Reserve
(
    const size_t aSize,
    const size_t aAlignment
)
{
    THROW_COND_GP
    (
        IsViewing() == false,
        "Storage is viewing"_sv
    );

    if (IsDataNullptr())
    {
        ClearAndAllocate(aSize, aAlignment);
        LockRW();
        return;
    }

    THROW_COND_GP
    (
        (Alignment() % aAlignment) == 0,
        "Wrong alignment"_sv
    );

    if (aSize <= iSizeAllocated)
    {
        return;
    }

    GpSecureStorage tmpStorage;
    tmpStorage.Reserve(aSize, Alignment());
    tmpStorage.CopyFrom(ViewR().R());
    Set(std::move(tmpStorage));
}

void    GpSecureStorage::Set (GpSecureStorage&& aStorage)
{
    if (this == &aStorage)
    {
        return;
    }

    THROW_COND_GP
    (
        aStorage.IsViewing() == false,
        "aStorage is viewing"_sv
    );

    THROW_COND_GP
    (
        IsViewing() == false,
        "Storage is viewing"_sv
    );

    Clear();

    iData           = aStorage.iData;
    iSizeUsed       = aStorage.iSizeUsed;
    iSizeAllocated  = aStorage.iSizeAllocated;
    iAlignment      = aStorage.iAlignment;

    aStorage.iData          = nullptr;
    aStorage.iSizeUsed      = 0;
    aStorage.iSizeAllocated = 0;
    aStorage.iAlignment     = 1;
}

void    GpSecureStorage::CopyFrom (const GpSecureStorage& aStorage)
{
    if (this == &aStorage)
    {
        return;
    }

    THROW_COND_GP
    (
        aStorage.IsViewing() == false,
        "aStorage is viewing"_sv
    );

    THROW_COND_GP
    (
        IsViewing() == false,
        "Storage is viewing"_sv
    );

    THROW_COND_GP
    (
        (Alignment() % aStorage.Alignment()) == 0,
        "Wrong alignment"_sv
    );

    CopyFrom(aStorage.ViewR().R());
}

void    GpSecureStorage::CopyFrom (GpSpanByteR aData)
{
    Resize(aData.Count());
    ViewRW().RW().CopyFrom(aData);
}

GpSecureStorageViewR    GpSecureStorage::ViewR (void) const
{
    THROW_COND_GP
    (
        IsViewing() == false,
        "Storage is viewing"_sv
    );

    return GpSecureStorageViewR(*this);
}

GpSecureStorageViewRW   GpSecureStorage::ViewRW (void)
{
    THROW_COND_GP
    (
        IsViewing() == false,
        "Storage is viewing"_sv
    );

    return GpSecureStorageViewRW(*this);
}

void    GpSecureStorage::LockRW (void) const
{
    if (iData == nullptr)
    {
        return;
    }

#if !defined(OS_BROWSER)
    if (sodium_mprotect_noaccess(iData) != 0)
    {
        THROW_GP("sodium_mprotect_noaccess return error"_sv);
    }
#endif//#if !defined(OS_BROWSER)
}

void    GpSecureStorage::UnlockRW (void)
{
    if (iData == nullptr)
    {
        return;
    }

#if !defined(OS_BROWSER)
    if (sodium_mprotect_readwrite(iData) != 0)
    {
        THROW_GP("sodium_mprotect_readwrite return error"_sv);
    }
#endif//#if !defined(OS_BROWSER)
}

void    GpSecureStorage::UnlockR (void) const
{
    if (iData == nullptr)
    {
        return;
    }

#if !defined(OS_BROWSER)
    if (sodium_mprotect_readonly(iData) != 0)
    {
        THROW_GP("sodium_mprotect_readonly return error"_sv);
    }
#endif//#if !defined(OS_BROWSER)
}

void    GpSecureStorage::SetViewing (const bool aValue) const
{
    THROW_COND_GP
    (
        iIsViewing != aValue,
        "Same value"_sv
    );

    iIsViewing = aValue;
}

GpSpanByteR GpSecureStorage::DataR (void) const
{
    return GpSpanByteR(iData, iSizeUsed);
}

GpSpanByteRW    GpSecureStorage::DataRW (void)
{
    return GpSpanByteRW(iData, iSizeUsed);
}

void    GpSecureStorage::ClearAndAllocate
(
    const size_t aSize,
    const size_t aAlignment
)
{
    Clear();

    THROW_COND_GP
    (
        (aSize >= 1) && (aSize <= 32768),
        "aSize is out of range"_sv
    );

    THROW_COND_GP
    (
        (aSize % aAlignment) == 0,
        "Wrong size for alignment"_sv
    );

#if defined(OS_BROWSER)
    iData = reinterpret_cast<std::byte*>(std::malloc(aSize));

    THROW_COND_GP
    (
        iData != nullptr,
        "std::malloc return nullptr"_sv
    );
#else
    iData = reinterpret_cast<std::byte*>(sodium_allocarray((aSize / aAlignment), aAlignment));

    THROW_COND_GP
    (
        iData != nullptr,
        "sodium_malloc return nullptr"_sv
    );
#endif

    iSizeAllocated  = aSize;
    iAlignment      = aAlignment;

#if !defined(OS_BROWSER)
    if (sodium_mlock(iData, iSizeAllocated) != 0)
    {
        Clear();
        THROW_GP("sodium_mlock return error"_sv);
    }
#endif//#if !defined(OS_BROWSER)
}

}// namespace GPlatform
