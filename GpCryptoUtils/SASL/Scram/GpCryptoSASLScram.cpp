#include <GpCrypto/GpCryptoUtils/SASL/Scram/GpCryptoSASLScram.hpp>
#include <GpCore2/GpUtils/Random/GpSRandom.hpp>
#include <GpCore2/GpUtils/Encoders/GpBase64.hpp>
#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_PBKDF2.hpp>
#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Sha2.hpp>

namespace GPlatform {

GpCryptoSASLScram::GpCryptoSASLScram
(
    const HashTypeT         aHashType,
    const KeyDerivationFnT  aKeyDerivationFn
) noexcept:
iHashType       {aHashType},
iKeyDerivationFn{aKeyDerivationFn}
{
}

GpCryptoSASLScram::~GpCryptoSASLScram (void) noexcept
{
}

GpCryptoSASLScram::SmallContainerT  GpCryptoSASLScram::ClientFirstMessage (GpSpanByteR aUserName)
{
    GenerateNonce();

    // Make message
    iClientFirstWithoutHeader = GpBytesArrayUtils::SMake<SmallContainerT>
    (
        fmt::format
        (
            "n={},r={}",
            aUserName.AsStringView(),
            GpSpanByteR{iNonce}.AsStringView()
        )
    );

    SmallContainerT clientFirstMessage = GpBytesArrayUtils::SMake<SmallContainerT>
    (
        fmt::format
        (
            "n,,{}",
            GpSpanByteR{iClientFirstWithoutHeader}.AsStringView()
        )
    );

    return clientFirstMessage;
}

GpCryptoSASLScram::SmallContainerT GpCryptoSASLScram::ClientFinalMessage
(
    GpSpanByteR aServerFirstMessage,
    GpSpanByteR aPassword
)
{
    // Check `iClientFirstWithoutHeader` size
    THROW_COND_GP
    (
        !iClientFirstWithoutHeader.empty(),
        "`iClientFirstWithoutHeader` is empty"_sv
    );

    // Check `aServerFirstMessage` size
    THROW_COND_GP
    (
        std::size(aServerFirstMessage) >= 16
        && (std::size(aServerFirstMessage) < (1024*10)),
        "`aServerFirstMessage` is exceeds the size limit"_sv
    );

    // Check `aPassword` size
    THROW_COND_GP
    (
        std::size(aPassword) > 0
        && (std::size(aPassword) <= 128),
        "`aPassword` is exceeds the size limit"_sv
    );

    // Extract attributes from server message
    SmallContainerT serverNonce;
    SmallContainerT salt;
    size_t          hashInterationsCount = 0;

    std::tie(serverNonce, salt, hashInterationsCount) = ParseServerFirstMessage(aServerFirstMessage);

    // Client final message without proof
    SmallContainerT clientAndServerNonce = iNonce;
    GpBytesArrayUtils::SAppend(clientAndServerNonce, serverNonce);

    const std::string clientFinalMessageWithoutProof = fmt::format
    (
        "c={},r={}",
        GpBase64::SEncode<std::string>("n,,"_sv, 8),
        GpSpanByteR{clientAndServerNonce}.AsStringView()
    );

    // Auth message
    iAuthMessage = GpBytesArrayUtils::SMake<SmallContainerT>
    (
        fmt::format
        (
            "{},{},{}",
            GpSpanByteR{iClientFirstWithoutHeader}.AsStringView(),
            aServerFirstMessage.AsStringView(),
            clientFinalMessageWithoutProof
        )
    );

    // Compute clientSignature
    GpSecureStorage::CSP        saltedPasswordCSP   = GpCryptoHash_PBKDF2::S_HmacSHA256(aPassword, salt, hashInterationsCount, 256_bit);
    iClientKey                                      = GpCryptoHash_Hmac::S_256("Client Key"_sv, saltedPasswordCSP->ViewR().R());
    iServerKey                                      = GpCryptoHash_Hmac::S_256("Server Key"_sv, saltedPasswordCSP->ViewR().R());
    GpCryptoHash_Sha2::Res256T  storedKey           = GpCryptoHash_Sha2::S_256(iClientKey);
    GpCryptoHash_Hmac::Res256T  clientSignature     = GpCryptoHash_Hmac::S_256(iAuthMessage, storedKey);

    // Compute clientProof = iClientKey XOR clientSignature
    SmallContainerT clientProof;
    clientProof.resize(32);

    for (size_t id = 0; id < 4; id++)
    {
        const size_t    offset          = id * sizeof(u_int_64);
        const u_int_64  keyPart         = MemOps::SCopyBitCast<u_int_64>(std::data(iClientKey) + offset);
        const u_int_64  signaturePart   = MemOps::SCopyBitCast<u_int_64>(std::data(clientSignature) + offset);
        const u_int_64  proofPart       = keyPart ^ signaturePart;

        std::memcpy(std::data(clientProof) + offset, &proofPart, sizeof(u_int_64));
    }

    // final client message
    SmallContainerT clientFinalMessage = GpBytesArrayUtils::SMake<SmallContainerT>
    (
        fmt::format
        (
            "{},p={}",
            clientFinalMessageWithoutProof,
            GpBase64::SEncode<std::string>(clientProof, 1024)
        )
    );

    return clientFinalMessage;
}

GpCryptoSASLScram::SmallContainerT  GpCryptoSASLScram::ServerFirstMessage ([[maybe_unused]] GpSpanByteR aClientFirstMessage)
{   
    // TODO: implement
    THROW_GP_NOT_IMPLEMENTED();
}

void    GpCryptoSASLScram::ValidateServerFinal (GpSpanByteR aServerFinalMessage)
{
    // Check `iAuthMessage` size
    THROW_COND_GP
    (
        !iAuthMessage.empty(),
        "`iAuthMessage` is empty"_sv
    );

    // Check `iServerKey` size
    THROW_COND_GP
    (
        !iServerKey.empty(),
        "`iServerKey` is empty"_sv
    );

    GpCryptoHash_Hmac::Res256T  serverSignature         = GpCryptoHash_Hmac::S_256(iAuthMessage, iServerKey);
    SmallContainerT             serverSignatureBase64   = GpBase64::SEncode<SmallContainerT>(serverSignature, 256);

    // Compare final message ans server signature
    THROW_COND_GP
    (
        GpSpanByteR{serverSignatureBase64} == ParseServerFinalMessage(aServerFinalMessage),
        "Server signature checking failed"
    );
}

void    GpCryptoSASLScram::GenerateNonce (void)
{
    iNonce = GpBytesArrayUtils::SMake<SmallContainerT>
    (
        GpSRandom::S().String(GpRandomStrMode::ALPHA_NUM_AND_SPECIAL, 24)
    );
}

GpCryptoSASLScram::ParseServerFirstResT GpCryptoSASLScram::ParseServerFirstMessage (GpSpanByteR aServerFirstMessage)
{
    // Result values
    SmallContainerT serverNonce;
    SmallContainerT salt;
    size_t          iterationsCount = 0;

    // Split message to parts
    const auto messageParts = Algo::Split<char, boost::container::small_vector<std::string_view, 8>>
    (
        GpSpanCharR{aServerFirstMessage},
        GpSpanCharR{","_sv},
        0,
        0,
        Algo::SplitMode::COUNT_ZERO_LENGTH_PARTS
    );

    // Read parts
    for (const std::string_view messagePart: messageParts)
    {
        //
        THROW_COND_GP
        (
            std::size(messagePart) >= 3,
            fmt::format
            (
                "Wrong value '{}'. [std::size(messagePart) >= 3]",
                messagePart
            )
        );

        const std::string_view prefix = messagePart.substr(0, 2);

        if (prefix == "r=")// Get serverNonce
        {
            const std::string_view value = messagePart.substr(2);

            // Check value length
            THROW_COND_GP
            (
                std::size(value) > std::size(iNonce),
                fmt::format
                (
                    "Wrong value '{}'. [std::size(value) > std::size(iNonce)]",
                    messagePart
                )
            );

            // Check value first part
            const std::string_view clientNonceFromServer = value.substr(0, std::size(iNonce));
            THROW_COND_GP
            (
                clientNonceFromServer == GpSpanByteR{iNonce}.AsStringView(),
                fmt::format
                (
                    "Wrong value '{}'. [clientNonceFromServer == iNonce]",
                    messagePart
                )
            );

            // Server nonce
            serverNonce = GpBytesArrayUtils::SMake<SmallContainerT>
            (
                value.substr(std::size(iNonce))
            );
        } else if (prefix == "s=")// Get salt
        {
            const std::string_view saltBase64 = messagePart.substr(2);
            salt = GpBase64::SDecode<SmallContainerT>(saltBase64);
        } else if (prefix == "i=")// Get hashInterationsCount
        {
            const std::string_view iterationsCountStr = messagePart.substr(2);
            iterationsCount = NumOps::SConvert<size_t>(StrOps::SToUI64(iterationsCountStr));
        } else
        {
            THROW_GP
            (
                fmt::format
                (
                    "Unknown part value '{}'",
                    messagePart
                )
            );
        }
    }

    // Check `serverNonce` value
    THROW_COND_GP
    (
        std::size(serverNonce) >= 8,
        "`serverNonce` is exceeds the size limit"
    );

    // Check `salt` value
    THROW_COND_GP
    (
        std::size(salt) >= 8,
        "`salt` is exceeds the size limit"
    );

    // Check `hashInterationsCount` value
    THROW_COND_GP
    (
           (iterationsCount >= 256)
        && (iterationsCount <= 8192),
        "`iterationsCount` is exceeds the size limit"
    );

    return {serverNonce, salt, iterationsCount};
}

GpSpanByteR GpCryptoSASLScram::ParseServerFinalMessage (GpSpanByteR aServerFinalMessage)
{
    // Split message to parts
    const auto messageParts = Algo::Split<char, boost::container::small_vector<std::string_view, 8>>
    (
        GpSpanCharR{aServerFinalMessage},
        GpSpanCharR{","_sv},
        0,
        0,
        Algo::SplitMode::COUNT_ZERO_LENGTH_PARTS
    );

    // Read parts
    for (const std::string_view messagePart: messageParts)
    {
        //
        THROW_COND_GP
        (
            std::size(messagePart) >= 3,
            fmt::format
            (
                "Wrong value '{}'. [std::size(messagePart) >= 3]",
                messagePart
            )
        );

        const std::string_view prefix = messagePart.substr(0, 2);

        if (prefix == "v=")// Get serverSignature
        {
            const std::string_view serverSignature = messagePart.substr(2);

            return serverSignature;
        }
    }

    return {};
}

}// namespace GPlatform
