#include <GpCrypto/GpCryptoCore/MnemonicCodes/GpCryptoMnemonicUtils.hpp>

#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Sha2.hpp>
#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_PBKDF2.hpp>
#include <GpCrypto/GpCryptoCore/Utils/GpCryptoRandom.hpp>
#include <GpCore2/GpUtils/Streams/GpByteWriter.hpp>
#include <GpCore2/GpUtils/Streams/GpByteWriterStorageFixedSize.hpp>

#include <utf8proc/utf8proc.hpp>

#if defined(RELEASE_BUILD_STATIC)
#   define SODIUM_STATIC
#endif

//GP_WARNING_PUSH()
//GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

//GP_WARNING_POP()

namespace GPlatform {

static const std::array<std::tuple<size_bit_t, size_bit_t, size_t>, size_t(GpCryptoMnemonicUtils::EntropySize::_LAST)>
GpCryptoMnemonicUtils_sMnemonicK =
{
    //ENT, CS, MS
    std::tuple<size_bit_t, size_bit_t, size_t>{128_bit, 4_bit, size_t{12}},// ES_128
    std::tuple<size_bit_t, size_bit_t, size_t>{160_bit, 5_bit, size_t{15}},// ES_160
    std::tuple<size_bit_t, size_bit_t, size_t>{192_bit, 6_bit, size_t{18}},// ES_192
    std::tuple<size_bit_t, size_bit_t, size_t>{224_bit, 7_bit, size_t{21}},// ES_224
    std::tuple<size_bit_t, size_bit_t, size_t>{256_bit, 8_bit, size_t{24}} // ES_256
};

GpSecureStorage::CSP    GpCryptoMnemonicUtils::SGenerateNewMnemonic
(
    const WordListT&    /*aWordList*/,
    const std::string   /*aSpaceChar*/,
    const EntropySize   aEntropySize
)
{
    const auto&         conf            = GpCryptoMnemonicUtils_sMnemonicK.at(size_t(aEntropySize));
    const size_bit_t    entropySize     = std::get<0>(conf);
    const size_bit_t    checksumLength  = std::get<1>(conf);
    //const size_t      wordsCount      = std::get<2>(conf);

    GpSecureStorage::CSP                entropySP       = GpCryptoRandom::SEntropy(entropySize.As<size_byte_t>().As<size_t>());
    const GpSecureStorage&              entropy         = entropySP.V();
    const GpSpanByteR                   entropySpanR    = entropy.ViewR().R();
    std::atomic_flag                    stopFlag;
    const GpCryptoHash_Sha2::Res256T    entropySha256   = GpCryptoHash_Sha2::S_256(entropy.ViewR().R(), entropySpanR.Count(), stopFlag, std::nullopt);
    const u_int_8                       checksumMask    = ~u_int_8((1 << (8 - checksumLength.As<size_t>()))-1);
    const u_int_8                       checksum        = u_int_8(u_int_8(entropySha256.at(0)) & checksumMask);

    GpSecureStorage entropyWithChecksum;
    entropyWithChecksum.Resize((entropySize + 1_byte/*cheksum*/).As<size_byte_t>().As<size_t>());

    {
        GpSecureStorageViewRW entropyWithChecksumViewRW = entropyWithChecksum.ViewRW();

        GpByteWriterStorageFixedSize    entropyWithChecksumStorage(entropyWithChecksumViewRW.RW());
        GpByteWriter                    entropyWithChecksumWriter(entropyWithChecksumStorage);

        entropyWithChecksumWriter.Bytes(entropy.ViewR().R());
        entropyWithChecksumWriter.UI8(checksum);
    }

    // Generate mnemonic phrase
    GpSecureStorage::SP mnemonicPhraseSP            = MakeSP<GpSecureStorage>();
    GpSecureStorage&    mnemonicPhrase              = mnemonicPhraseSP.V();
    size_t              mnemonicPhraseActualSize    = 0;

    {
        //TODO: implement
        THROW_GP_NOT_IMPLEMENTED();

        /*
        const size_t            spaceSize   = std::size(aSpaceChar);
        constexpr const size_t  maxWordSize = 10;
        mnemonicPhrase.Resize
        (
            wordsCount*maxWordSize + (wordsCount - 1)*spaceSize
        );

        GpSecureStorageViewRW           mnemonicPhraseViewRW    = mnemonicPhrase.ViewRW();
        GpByteWriterStorageFixedSize    mnemonicPhraseStorage(mnemonicPhraseViewRW.RW());
        GpByteWriter                    mnemonicPhraseWriter(mnemonicPhraseStorage);

        GpSecureStorageViewR    entropyWithChecksumViewR = entropyWithChecksum.ViewR();
        GpBitReader             entropyBitReader(entropyWithChecksumViewR.R());

        for (size_t wordId = 0; wordId < wordsCount; ++wordId)
        {
            if (wordId > 0)
            {
                mnemonicPhraseWriter.Bytes(aSpaceChar);
            }

            const u_int_16 wid = entropyBitReader.UI16(11_bit, 0_bit);
            mnemonicPhraseWriter.Bytes(aWordList.at(wid));
        }

        mnemonicPhraseActualSize = mnemonicPhraseWriter.TotalWrite();
        */
    }

    mnemonicPhrase.Resize(mnemonicPhraseActualSize);

    return mnemonicPhraseSP;
}

bool    GpCryptoMnemonicUtils::SValidateMnemonic
(
    const WordListT&        aWordList,
    const std::string       aSpaceChar,
    const GpSecureStorage&  aMnemonic
)
{
    return SValidateMnemonic(aWordList, aSpaceChar, aMnemonic.ViewR().R());
}

bool    GpCryptoMnemonicUtils::SValidateMnemonic
(
    const WordListT&    /*aWordList*/,
    const std::string   aSpaceChar,
    GpSpanCharR         aMnemonic
)
{
    std::vector<std::string_view> mnemonicWords = StrOps::SSplit
    (
        aMnemonic.AsStringView(),
        aSpaceChar,
        0,
        0,
        Algo::SplitMode::SKIP_ZERO_LENGTH_PARTS
    );

    const auto& conf = GpCryptoMnemonicUtils_sMnemonicK.at(SFindConfByWordsCount(std::size(mnemonicWords)));

    const size_bit_t    entropySize     = std::get<0>(conf);
    const size_bit_t    checksumLength  = std::get<1>(conf);
    //const u_int_8     checksumMask    = ~u_int_8((1 << (8 - checksumLength.As<size_t>()))-1);

    // ------------- Reconstruct entropy with checksum ---------------
    GpSecureStorage entropyWithChecksum;
    entropyWithChecksum.Resize((entropySize + 1_byte/*cheksum*/).As<size_byte_t>().As<size_t>());
    {
        //TODO: implement
        THROW_GP_NOT_IMPLEMENTED();

        /*GpSecureStorageViewRW entropyWithChecksumViewRW = entropyWithChecksum.ViewRW();

        GpBitWriterStorageFixedSize entropyWithChecksumStorage(entropyWithChecksumViewRW.RW());
        GpBitWriter                 entropyWithChecksumWriter(entropyWithChecksumStorage);

        for (std::string_view word: mnemonicWords)
        {
            const u_int_16 wid = SFindWordId(aWordList, word);
            entropyWithChecksumWriter.UI16(wid, 11_bit);
        }*/
    }

    // ------------- Calculate checksum ---------------
    {
        //TODO: implement
        THROW_GP_NOT_IMPLEMENTED();

        /*const size_t entropCnt = size_byte_t(entropySize).As<size_t>();

        GpSecureStorageViewR            entropyWithChecksumViewR    = entropyWithChecksum.ViewR();
        GpSpanByteR                     entropyWithChecksumPtrR     = entropyWithChecksumViewR.R();
        GpSpanByteR                     entropy                     = entropyWithChecksumPtrR.Subspan(0, entropCnt);
        const GpCryptoHash_Sha2::Res256T    entropySha256 = GpCryptoHash_Sha2::S_256(entropy);

        const u_int_8 checksumIn    = u_int_8(entropyWithChecksumPtrR.At(entropCnt));
        const u_int_8 checksumCalc  = u_int_8(u_int_8(entropySha256.at(0)) & checksumMask);

        return   (checksumIn   & checksumMask)
                == (checksumCalc & checksumMask);

        //TODO check GpBitWriter

        return true;*/
    }
}

GpSecureStorage::CSP    GpCryptoMnemonicUtils::SSeedFromMnemonic
(
    const WordListT&        aWordList,
    const std::string       aSpaceChar,
    const GpSecureStorage&  aMnemonic,
    const GpSecureStorage&  aPassword,
    const size_t            aIterations,
    const size_bit_t        aBitLengthDerivedKey
)
{
    return SSeedFromMnemonic
    (
        aWordList,
        aSpaceChar,
        aMnemonic.ViewR().R(),
        aPassword.ViewR().R(),
        aIterations,
        aBitLengthDerivedKey
    );
}

GpSecureStorage::CSP    GpCryptoMnemonicUtils::SSeedFromMnemonic
(
    const WordListT&    aWordList,
    const std::string   aSpaceChar,
    GpSpanCharR         aMnemonic,
    GpSpanCharR         aPassword,
    const size_t        aIterations,
    const size_bit_t    aBitLengthDerivedKey
)
{
    THROW_COND_GP
    (
        aMnemonic.Count() > 0,
        "Mnemonic is empty"_sv
    );

    // Validate mnemonic
    THROW_COND_GP
    (
        SValidateMnemonic(aWordList, aSpaceChar, aMnemonic),
        "Invalid mnemonic phrase"_sv
    );

    // Mnemonic normalization
    GpSecureStorage normalizedMnemonic;
    {
        const size_t cnt = UTF8Proc::S_MaxCountUTF32(UTF8NFType::NFKD, aMnemonic.AsStringView());

        GpSecureStorage tmpStorage;
        tmpStorage.Resize
        (
            cnt * GpSpanSI32_RW::value_size_v,
            alignof(GpSpanSI32_RW::value_type)
        );

        GpSecureStorageViewRW   tmpStorageViewRW    = tmpStorage.ViewRW();
        GpSpanSI32_RW           tmpStoragePtrRW     = tmpStorageViewRW.RW().ReinterpretAs<GpSpanSI32_RW>();

        const size_t actualSize = UTF8Proc::S_Process(UTF8NFType::NFKD, aMnemonic.AsStringView(), tmpStoragePtrRW);
        normalizedMnemonic.CopyFrom(tmpStoragePtrRW.As<GpSpanByteR>().Subspan(0, actualSize));
    }

    // Password normalization
    GpSecureStorage normalizedPassword;
    if (aPassword.Count() > 0)
    {
        const size_t cnt = UTF8Proc::S_MaxCountUTF32(UTF8NFType::NFKD, aPassword.AsStringView());

        GpSecureStorage tmpStorage;
        tmpStorage.Resize
        (
            cnt * GpSpanSI32_RW::value_size_v,
            alignof(GpSpanSI32_RW::value_type)
        );
        GpSecureStorageViewRW   tmpStorageViewRW    = tmpStorage.ViewRW();
        GpSpanSI32_RW           tmpStoragePtrRW     = tmpStorageViewRW.RW().ReinterpretAs<GpSpanSI32_RW>();

        const size_t actualSize = UTF8Proc::S_Process(UTF8NFType::NFKD, aPassword.AsStringView(), tmpStoragePtrRW);
        normalizedPassword.CopyFrom(tmpStoragePtrRW.As<GpSpanByteR>().Subspan(0, actualSize));
    }

    // Salt
    GpSecureStorage salt;
    {
        std::string_view    saltPrefix  = "mnemonic"_sv;
        size_t              saltSize    = std::size(saltPrefix);

        if (!normalizedPassword.Empty())
        {
            saltSize += normalizedPassword.Size();
        }

        salt.Resize(saltSize);

        GpSecureStorageViewRW           saltViewRW = salt.ViewRW();
        GpByteWriterStorageFixedSize    saltStorage(saltViewRW.RW());
        GpByteWriter                    saltWriter(saltStorage);

        saltWriter.Bytes(saltPrefix);

        if (!normalizedPassword.Empty())
        {
            saltWriter.Bytes(normalizedPassword.ViewR().R());
        }
    }

    GpSecureStorage::CSP res = GpCryptoHash_PBKDF2::S_HmacSHA512
    (
        normalizedMnemonic.ViewR().R(),
        salt.ViewR().R(),
        aIterations,
        aBitLengthDerivedKey
    );

    return res;
}

size_t  GpCryptoMnemonicUtils::SFindConfByWordsCount (const size_t aWordsCount)
{
    for (size_t id = 0; id < size_t(EntropySize::_LAST); ++id)
    {
        const auto&     conf        = GpCryptoMnemonicUtils_sMnemonicK.at(id);
        const size_t    wordsCount  = std::get<2>(conf);

        if (aWordsCount == wordsCount)
        {
            return id;
        }
    }

    THROW_GP("Wrong words count"_sv);
}

u_int_16    GpCryptoMnemonicUtils::SFindWordId
(
    const WordListT&    aWordList,
    GpSpanCharR         aWord
)
{
    std::string_view word = aWord.AsStringView();
    size_t id = 0;
    for (const auto& wordFromList: aWordList)
    {
        if (word == wordFromList)
        {
            return u_int_16(id);
        }

        ++id;
    }

    THROW_GP("Word '"_sv + word + "' was not found in list"_sv);
}

}// namespace GPlatform
