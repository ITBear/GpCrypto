#pragma once

#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorageViewR.hpp>
#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorageViewRW.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpSecureStorage
{
    friend class GpSecureStorageViewR;
    friend class GpSecureStorageViewRW;

public:
    CLASS_REMOVE_CTRS_MOVE_COPY(GpSecureStorage)
    CLASS_DD(GpSecureStorage)

public:
                            GpSecureStorage     (void) noexcept;
                            ~GpSecureStorage    (void) noexcept;

    void                    Clear               (void);
    void                    Resize              (size_t aSize);
    void                    Resize              (size_t aSize, size_t aAlignment);
    void                    Reserve             (size_t aSize);
    void                    Reserve             (size_t aSize, size_t aAlignment);
    size_t                  Size                (void) const noexcept {return iSizeUsed;}
    bool                    Empty               (void) const noexcept {return iSizeUsed == 0;}
    size_t                  Alignment           (void) const noexcept {return iAlignment;}
    bool                    IsDataNullptr       (void) const noexcept {return iData == nullptr;}
    bool                    IsViewing           (void) const noexcept {return iIsViewing;}

    void                    Set                 (GpSecureStorage&& aStorage);
    void                    CopyFrom            (const GpSecureStorage& aStorage);
    void                    CopyFrom            (GpSpanByteR aData);

    GpSecureStorageViewR    ViewR               (void) const;
    GpSecureStorageViewRW   ViewRW              (void);

protected:
    void                    LockRW              (void) const;
    void                    UnlockRW            (void);
    void                    UnlockR             (void) const;
    void                    SetViewing          (bool aValue) const;
    GpSpanByteR             DataR               (void) const;
    GpSpanByteRW            DataRW              (void);

private:
    void                    ClearAndAllocate    (size_t aSize, size_t aAlignment);

private:
    std::byte*              iData           = nullptr;
    size_t                  iSizeUsed       = 0;
    size_t                  iSizeAllocated  = 0;
    size_t                  iAlignment      = 1;
    mutable bool            iIsViewing      = false;
};

}// namespace GPlatform
