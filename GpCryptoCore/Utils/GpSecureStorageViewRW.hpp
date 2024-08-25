#pragma once

#include <GpCore2/GpUtils/Macro/GpMacroClass.hpp>
#include <GpCore2/GpUtils/Types/Containers/GpContainersT.hpp>
#include <GpCore2/GpUtils/Types/Containers/GpBytesArray.hpp>
#include <GpCrypto/GpCryptoCore/GpCryptoCore_global.hpp>

namespace GPlatform {

class GpSecureStorage;

class GP_CRYPTO_CORE_API GpSecureStorageViewRW
{
    friend class GpSecureStorage;

public:
    CLASS_REMOVE_CTRS_DEFAULT_COPY(GpSecureStorageViewRW)
    CLASS_DD(GpSecureStorageViewRW)

    using StorageOptT = std::optional<std::reference_wrapper<GpSecureStorage>>;

private:
                            GpSecureStorageViewRW   (GpSecureStorage& aStorage);

public:
                            GpSecureStorageViewRW   (GpSecureStorageViewRW&& aView) noexcept;
                            ~GpSecureStorageViewRW  (void) noexcept;

    GpSecureStorageViewRW&  operator=               (GpSecureStorageViewRW&& aView);

    GpSpanByteR             R                       (void) const;
    GpSpanByteRW            RW                      (void);
    size_t                  Size                    (void) const noexcept;
    bool                    IsEmpty                 (void) const noexcept {return Size() == 0;}

    void                    Release                 (void);

private:
    StorageOptT             iStorage;
};

}// namespace GPlatform
