#pragma once

#include <GpCore2/GpUtils/Macro/GpMacroClass.hpp>
#include <GpCore2/GpUtils/Types/Containers/GpContainersT.hpp>
#include <GpCore2/GpUtils/Types/Containers/GpBytesArray.hpp>
#include <GpCrypto/GpCryptoCore/GpCryptoCore_global.hpp>

namespace GPlatform {

class GpSecureStorage;

class GP_CRYPTO_CORE_API GpSecureStorageViewR
{
    friend class GpSecureStorage;

public:
    CLASS_REMOVE_CTRS_DEFAULT_COPY(GpSecureStorageViewR)
    CLASS_DD(GpSecureStorageViewR)

    using StorageOptT = std::optional<std::reference_wrapper<const GpSecureStorage>>;

private:
                            GpSecureStorageViewR    (const GpSecureStorage& aStorage);

public:
                            GpSecureStorageViewR    (GpSecureStorageViewR&& aView) noexcept;
                            ~GpSecureStorageViewR   (void) noexcept;

    GpSecureStorageViewR&   operator=               (GpSecureStorageViewR&& aView);

    GpSpanByteR             R                       (void) const;

    size_t                  Size                    (void) const noexcept;
    bool                    IsEmpty                 (void) const noexcept {return Size() == 0;}

    void                    Release                 (void);

private:
    StorageOptT             iStorage;
};

}// namespace GPlatform
