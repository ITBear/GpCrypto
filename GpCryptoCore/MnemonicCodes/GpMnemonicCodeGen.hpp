#pragma once

#include <GpCrypto/GpCryptoCore/Utils/GpSecureStorage.hpp>
#include <GpCore2/GpUtils/Types/Units/Other/size_byte_t.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpMnemonicCodeGen
{
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpMnemonicCodeGen)

public:
    using WordListT = std::array<std::string, 2048>;

    enum EntropySize
    {
        ES_128,
        ES_160,
        ES_192,
        ES_224,
        ES_256,
        _LAST
    };

public:
    static GpSecureStorage::CSP     SGenerateNewMnemonic    (const WordListT&   aWordList,
                                                             std::string        aSpaceChar,
                                                             EntropySize        aEntropySize);

    [[nodiscard]] static bool       SValidateMnemonic       (const WordListT&       aWordList,
                                                             std::string            aSpaceChar,
                                                             const GpSecureStorage& aMnemonic);

    [[nodiscard]] static bool       SValidateMnemonic       (const WordListT&   aWordList,
                                                             std::string        aSpaceChar,
                                                             GpSpanCharR        aMnemonic);

    static GpSecureStorage::CSP     SSeedFromMnemonic       (const WordListT&       aWordList,
                                                             std::string            aSpaceChar,
                                                             const GpSecureStorage& aMnemonic,
                                                             const GpSecureStorage& aPassword,
                                                             size_t                 aIterations,
                                                             size_bit_t             aBitLengthDerivedKey);

    static GpSecureStorage::CSP     SSeedFromMnemonic       (const WordListT&   aWordList,
                                                             std::string        aSpaceChar,
                                                             GpSpanCharR        aMnemonic,
                                                             GpSpanCharR        aPassword,
                                                             size_t             aIterations,
                                                             size_bit_t         aBitLengthDerivedKey);
private:
    static size_t                   SFindConfByWordsCount   (size_t aWordsCount);
    static u_int_16                 SFindWordId             (const WordListT&   aWordList,
                                                             GpSpanCharR        aWord);
};

}// namespace GPlatform
