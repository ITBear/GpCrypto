#pragma once

#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>
#include <GpCore2/GpUtils/Types/Units/Other/size_byte_t.hpp>
#include <GpCore2/GpUtils/Types/Units/Other/size_mebibyte_t.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoHash_KDF_Passwd
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHash_KDF_Passwd)

public:
    static GpSecureStorage::CSP S_H (GpSpanByteR    aPassword,
                                     GpSpanByteR    aSalt,
                                     size_bit_t     aBitLengthDerivedKey,
                                     size_mibyte_t  aMemoryLimit = 32_MiB);

};

}// namespace GPlatform
