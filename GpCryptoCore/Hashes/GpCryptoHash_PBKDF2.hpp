#pragma once

#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>
#include <GpCore2/GpUtils/Types/Units/Other/size_byte_t.hpp>
#include <GpCore2/GpUtils/Types/Units/Other/size_mebibyte_t.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoHash_PBKDF2
{
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHash_PBKDF2)

public:
    static GpSecureStorage::CSP     S_HmacSHA512    (GpSpanByteR    aPassword,
                                                     GpSpanByteR    aSalt,
                                                     size_t         aIterations,
                                                     size_bit_t     aBitLengthDerivedKey);
    static GpSecureStorage::CSP     S_HmacSHA256    (GpSpanByteR    aPassword,
                                                     GpSpanByteR    aSalt,
                                                     size_t         aIterations,
                                                     size_bit_t     aBitLengthDerivedKey);
};

}// namespace GPlatform
