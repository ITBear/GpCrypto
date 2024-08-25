#pragma once

#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>
#include <GpCore2/GpUtils/Streams/GpByteWriterStorage.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpByteWriterStorageSecure final: public GpByteWriterStorage
{
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpByteWriterStorageSecure)

public:
    inline                  GpByteWriterStorageSecure   (GpSecureStorage& aStorage) noexcept;
    virtual                 ~GpByteWriterStorageSecure  (void) noexcept override final;

protected:
    virtual void            AllocateAdd                 (const size_t   aSizeToAdd,
                                                         GpSpanByteRW&  aStoragePtr) override final;
    virtual void            _OnEnd                      (void) override final;

private:
    GpSecureStorageViewRW   iViewRW;
    GpSecureStorage&        iStorage;
};

GpByteWriterStorageSecure::GpByteWriterStorageSecure (GpSecureStorage& aStorage) noexcept:
GpByteWriterStorage{aStorage.ViewRW().RW()},
iViewRW {aStorage.ViewRW()},
iStorage{aStorage}
{
}

}// namespace GPlatform
