#include <GpCrypto/GpCryptoUtils/SASL/Scram/GpCryptoSASLScram.hpp>
#include <GpCore2/GpUtils/Random/GpSRandom.hpp>
#include <GpCore2/GpUtils/Encoders/GpBase64.hpp>
#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_PBKDF2.hpp>
#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Sha2.hpp>

#include <iostream>

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

void    GpCryptoSASLScram::Reset (void) noexcept
{
    iClientUserName.clear();
    iClientNonce.clear();
    iServerNonce.clear();
    iServerSalt.clear();
    iClientFirstWithoutHeader.clear();
    iServerFirstMessage.clear();
    iIterationsCount = 4096;
}

GpCryptoSASLScram::SmallContainerT  GpCryptoSASLScram::ClientFirstMessage (GpSpanByteR aUserName)
{
    // Check `aUserName` size
    THROW_COND_GP
    (
        std::size(aUserName) > 0
        && (std::size(aUserName) <= 128),
        "`aUserName` is outside the size limit"_sv
    );

    iClientNonce    = SGenerateNonce();
    iClientUserName = GpBytesArrayUtils::SMake<SmallContainerT>(aUserName.AsStringView());

    // Make message
    iClientFirstWithoutHeader = GpBytesArrayUtils::SMake<SmallContainerT>
    (
        fmt::format
        (
            "n={},r={}",
            aUserName.AsStringView(),
            GpSpanByteR{iClientNonce}.AsStringView()
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

    // Check `aPassword` size
    THROW_COND_GP
    (
        std::size(aPassword) > 0
        && (std::size(aPassword) <= 128),
        "`aPassword` is outside the size limit"_sv
    );

    // Extract attributes from server message
    const auto [serverNonce, clientNonceFromServer, serverSalt, iterationsCount] = SParseServerFirstMessage(aServerFirstMessage, std::size(iClientNonce));

    iServerNonce        = GpBytesArrayUtils::SMake<SmallContainerT>(serverNonce);
    iServerSalt         = GpBytesArrayUtils::SMake<SmallContainerT>(serverSalt);
    iIterationsCount    = iterationsCount;

    // Check iClientNonce
    THROW_COND_GP
    (
        GpSpanByteR{iClientNonce}.AsStringView() == clientNonceFromServer,
        "Incorrect client Nonce received from server"
    );

    // Make proof
    SmallContainerT clientFinalMessageWithoutProof;
    SmallContainerT clientProof;

    std::tie(iClientKey, iServerKey, iAuthMessage, clientFinalMessageWithoutProof, clientProof) = SMakeProof
    (
        iClientNonce,
        iServerNonce,
        iClientFirstWithoutHeader,
        aServerFirstMessage,
        iServerSalt,
        iIterationsCount,
        aPassword
    );

    // final client message
    SmallContainerT clientFinalMessage = GpBytesArrayUtils::SMake<SmallContainerT>
    (
        fmt::format
        (
            "{},p={}",
            GpSpanByteR{clientFinalMessageWithoutProof}.AsStringView(),
            GpBase64::SEncode<std::string>(clientProof, 1024)
        )
    );

    return clientFinalMessage;
}

void    GpCryptoSASLScram::ValidateServerFinal (GpSpanByteR aServerFinalMessage)
{
    // Check `aServerFinalMessage` size
    THROW_COND_GP
    (
        std::size(aServerFinalMessage) > 0
        && (std::size(aServerFinalMessage) <= 8192),
        "`aServerFinalMessage` is outside the size limit"_sv
    );

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
        GpSpanByteR{serverSignatureBase64} == SParseServerFinalMessage(aServerFinalMessage),
        "Server signature checking failed"
    );
}

#if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)

GpCryptoSASLScram::SmallContainerT  GpCryptoSASLScram::ServerFirstMessage (GpSpanByteR aClientFirstMessage)
{   
    // Extract attributes from client message
    const auto [clientNonce, clientUserName, clientFirstWithoutHeader] = SParseClientFirstMessage(aClientFirstMessage);

    iClientUserName             = GpBytesArrayUtils::SMake<SmallContainerT>(clientUserName);
    iClientNonce                = GpBytesArrayUtils::SMake<SmallContainerT>(clientNonce);
    iServerNonce                = SGenerateNonce();
    iServerSalt                 = SGenerateSalt();
    iClientFirstWithoutHeader   = GpBytesArrayUtils::SMake<SmallContainerT>(clientFirstWithoutHeader);
    iIterationsCount            = 4096;

    // First server message (r=<client nonce><server nonce>,s=<base64 encoded salt>,i=<iteration count>)
    iServerFirstMessage = GpBytesArrayUtils::SMake<SmallContainerT>
    (
        fmt::format
        (
            "r={}{},s={},i={}",
            GpSpanByteR{iClientNonce}.AsStringView(),
            GpSpanByteR{iServerNonce}.AsStringView(),
            GpBase64::SEncode<std::string>(iServerSalt, 1024),
            iIterationsCount
        )
    );

    return iServerFirstMessage;
}

GpCryptoSASLScram::SmallContainerT  GpCryptoSASLScram::ServerFinalMessage
(
    GpSpanByteR aClientFinalMessage,
    GpSpanByteR aUserName,
    GpSpanByteR aPassword
)
{
    // Check `iClientFirstWithoutHeader` size
    THROW_COND_GP
    (
        !iClientFirstWithoutHeader.empty(),
        "`iClientFirstWithoutHeader` is empty"_sv
    );

    // Check `aUserName` size
    THROW_COND_GP
    (
        std::size(aUserName) > 0
        && (std::size(aUserName) <= 128),
        "`aUserName` is outside the size limit"_sv
    );

    // Check `aPassword` size
    THROW_COND_GP
    (
        std::size(aPassword) > 0
        && (std::size(aPassword) <= 128),
        "`aPassword` is outside the size limit"_sv
    );

    // Extract attributes from client message
    const auto [clientFinalMessageWithoutProof, clientProof] = SParseClientFinalMessage(aClientFinalMessage);

    // Make proof
    SmallContainerT calulatedClientFinalMessageWithoutProof;
    SmallContainerT calulatedClientProof;

    std::tie(iClientKey, iServerKey, iAuthMessage, calulatedClientFinalMessageWithoutProof, calulatedClientProof) = SMakeProof
    (
        iClientNonce,
        iServerNonce,
        iClientFirstWithoutHeader,
        iServerFirstMessage,
        iServerSalt,
        iIterationsCount,
        aPassword
    );

    // Validate client
    std::string_view _calulatedClientFinalMessageWithoutProof = GpSpanByteR{calulatedClientFinalMessageWithoutProof}.AsStringView().substr(std::size("c=biws,r=") - 1);

    THROW_COND_GP
    (
           (GpSpanByteR{iClientUserName}.AsStringView() == aUserName.AsStringView())
        && (clientFinalMessageWithoutProof == _calulatedClientFinalMessageWithoutProof)
        && (GpBase64::SDecode<SmallContainerT>(clientProof) == calulatedClientProof),
        [&]()
        {
            return fmt::format
            (
                "Authentication failed for user '{}'",
                GpSpanByteR{iClientUserName}.AsStringView()
            );
        }
    );

    // final server message (v=<server signature base 64>)
    const GpCryptoHash_Hmac::Res256T    serverSignature     = GpCryptoHash_Hmac::S_256(iAuthMessage, iServerKey);
    const SmallContainerT               serverFinalMessage  = GpBytesArrayUtils::SMake<SmallContainerT>
    (
        fmt::format
        (
            "v={}",
            GpBase64::SEncode<std::string>(serverSignature, 256)
        )
    );

    return serverFinalMessage;
}

#endif// #if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)

GpCryptoSASLScram::SmallContainerT  GpCryptoSASLScram::SGenerateNonce (void)
{
    return GpBytesArrayUtils::SMake<SmallContainerT>
    (
        GpSRandom::S().String(GpRandomStrMode::ALPHA_NUM_AND_SPECIAL, 24)
    );
}

GpCryptoSASLScram::ParseServerFirstResT GpCryptoSASLScram::SParseServerFirstMessage
(
    GpSpanByteR     aServerFirstMessage,
    const size_t    aClientNonceSize
)
{
    // Check `aServerFirstMessage` size
    THROW_COND_GP
    (
        std::size(aServerFirstMessage) > 0
        && (std::size(aServerFirstMessage) <= 8192),
        "`aServerFirstMessage` is outside the size limit"_sv
    );

    // Result values
    std::string_view    serverNonce;
    std::string_view    clientNonceFromServer;
    SmallContainerT     serverSalt;
    size_t              iterationsCount = 4096;

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
                std::size(value) > aClientNonceSize,
                fmt::format
                (
                    "Wrong value '{}'. [std::size(value) > aClientNonceSize]",
                    messagePart
                )
            );

            // Check value first part
            clientNonceFromServer = value.substr(0, aClientNonceSize);

            // Server nonce
            serverNonce = value.substr(aClientNonceSize);
        } else if (prefix == "s=")// Get serverSalt
        {
            const std::string_view serverSaltBase64 = messagePart.substr(2);
            serverSalt = GpBase64::SDecode<SmallContainerT>(serverSaltBase64);
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
        "`serverNonce` is outside the size limit"
    );

    // Check `serverSalt` value
    THROW_COND_GP
    (
        std::size(serverSalt) >= 8,
        "`serverSalt` is outside the size limit"
    );

    // Check `hashInterationsCount` value
    THROW_COND_GP
    (
           (iterationsCount >= 256)
        && (iterationsCount <= 8192),
        "`iterationsCount` is outside the size limit"
    );

    return
    {
        serverNonce,
        clientNonceFromServer,
        serverSalt,
        iterationsCount
    };
}

GpSpanByteR GpCryptoSASLScram::SParseServerFinalMessage (GpSpanByteR aServerFinalMessage)
{
    // Check `aServerFinalMessage` size
    THROW_COND_GP
    (
        std::size(aServerFinalMessage) > 0
        && (std::size(aServerFinalMessage) <= 8192),
        "`aServerFinalMessage` is outside the size limit"_sv
    );

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
    std::string_view serverSignature;
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
            serverSignature = messagePart.substr(2);
        }
    }

    // Check 'serverSignature'
    THROW_COND_GP
    (
        std::size(serverSignature) >= 8,
        "`serverSignature` is outside the size limit"
    );

    return serverSignature;
}

#if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)

GpCryptoSASLScram::SmallContainerT  GpCryptoSASLScram::SGenerateSalt (void)
{
    GpCryptoSASLScram::SmallContainerT res;

    GpSRandom::S().BytesArray<SmallContainerT>(res, 8);

    return res;
}

GpCryptoSASLScram::ParseClientFirstResT GpCryptoSASLScram::SParseClientFirstMessage (GpSpanByteR aClientFirstMessage)
{
    // Check `aClientFirstMessage` size
    THROW_COND_GP
    (
        std::size(aClientFirstMessage) > 0
        && (std::size(aClientFirstMessage) <= 8192),
        "`aClientFirstMessage` is outside the size limit"_sv
    );

    // Check prefix 'n,,'
    std::string_view clientFirstWithoutHeader;
    {
        std::string_view message = aClientFirstMessage.AsStringView();

        THROW_COND_GP
        (
               (std::size(message) > std::size("n,,"))
            && (message.substr(0, 3) == "n,,"),
            "Prefix must be 'n,,'"
        );

        clientFirstWithoutHeader = message.substr(3);
    }

    // Split message to parts
    const auto messageParts = Algo::Split<char, boost::container::small_vector<std::string_view, 8>>
    (
        GpSpanCharR{clientFirstWithoutHeader},
        GpSpanCharR{","_sv},
        0,
        0,
        Algo::SplitMode::COUNT_ZERO_LENGTH_PARTS
    );

    // Read parts
    std::string_view clientUserName;
    std::string_view clientNonce;

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

        if (prefix == "n=")// Get client user name
        {
            clientUserName = messagePart.substr(2);
        } else if (prefix == "r=")// Get client nonce
        {
            clientNonce = messagePart.substr(2);
        }
    }

    // Check `clientUserName` value
    // Check `aUserName` size
    THROW_COND_GP
    (
        std::size(clientUserName) > 0
        && (std::size(clientUserName) <= 128),
        "`clientUserName` is outside the size limit"_sv
    );

    // Check `clientNonce` value
    THROW_COND_GP
    (
        std::size(clientNonce) >= 8,
        "`clientNonce` is outside the size limit"
    );

    return
    {
        clientNonce,
        clientUserName,
        clientFirstWithoutHeader
    };
}

GpCryptoSASLScram::ParseClientFinalResT GpCryptoSASLScram::SParseClientFinalMessage (GpSpanByteR aClientFinalMessage)
{
    // Check `aClientFinalMessage` size
    THROW_COND_GP
    (
        std::size(aClientFinalMessage) > 0
        && (std::size(aClientFinalMessage) <= 8192),
        "`aClientFinalMessage` is outside the size limit"_sv
    );

    // Check prefix 'c=biws,'
    std::string_view    message     = aClientFinalMessage.AsStringView();
    const size_t        messageSize = std::size(message);

    THROW_COND_GP
    (
           (messageSize > std::size("c=biws,"))
        && (message.substr(0, 7) == "c=biws,"),
        "Prefix must be 'c=biws,'"
    );

    // Split message to parts
    message = message.substr(7);

    const auto messageParts = Algo::Split<char, boost::container::small_vector<std::string_view, 8>>
    (
        GpSpanCharR{message},
        GpSpanCharR{","_sv},
        0,
        0,
        Algo::SplitMode::COUNT_ZERO_LENGTH_PARTS
    );

    // Read parts
    std::string_view clientFinalMessageWithoutProof;
    std::string_view clientProof;

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

        if (prefix == "r=")// Get client clientFinalMessageWithoutProof
        {
            clientFinalMessageWithoutProof = messagePart.substr(2);
        } else if (prefix == "p=")// Get client nonce
        {
            clientProof = messagePart.substr(2);
        }
    }

    // Check `clientFinalMessageWithoutProof` value
    THROW_COND_GP
    (
        std::size(clientFinalMessageWithoutProof) >= 10,
        "`clientFinalMessageWithoutProof` is outside the size limit"
    );

    // Check `clientProof` value
    THROW_COND_GP
    (
        std::size(clientProof) >= 8,
        "`clientProof` is outside the size limit"
    );

    return
    {
        clientFinalMessageWithoutProof,
        clientProof
    };
}

#endif// #if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)

GpCryptoSASLScram::ProofResT    GpCryptoSASLScram::SMakeProof
(
    GpSpanByteR     aClientNonce,
    GpSpanByteR     aServerNonce,
    GpSpanByteR     aClientFirstWithoutHeader,
    GpSpanByteR     aServerFirstMessage,
    GpSpanByteR     aServerSalt,
    const size_t    aIterationsCount,
    GpSpanByteR     aPassword
)
{
    // Client final message without proof
    SmallContainerT clientAndServerNonce;
    GpBytesArrayUtils::SAppend(clientAndServerNonce, aClientNonce);
    GpBytesArrayUtils::SAppend(clientAndServerNonce, aServerNonce);

    const std::string clientFinalMessageWithoutProof = fmt::format
    (
        "c={},r={}",
        GpBase64::SEncode<std::string>("n,,"_sv, 8),
        GpSpanByteR{clientAndServerNonce}.AsStringView()
    );

    // Auth message
    SmallContainerT authMessage = GpBytesArrayUtils::SMake<SmallContainerT>
    (
        fmt::format
        (
            "{},{},{}",
            GpSpanByteR{aClientFirstWithoutHeader}.AsStringView(),
            aServerFirstMessage.AsStringView(),
            clientFinalMessageWithoutProof
        )
    );

    // Compute clientSignature
    GpSecureStorage::CSP        saltedPasswordCSP   = GpCryptoHash_PBKDF2::S_HmacSHA256(aPassword, aServerSalt, aIterationsCount, 256_bit);
    GpCryptoHash_Hmac::Res256T  clientKey           = GpCryptoHash_Hmac::S_256("Client Key"_sv, saltedPasswordCSP->ViewR().R());
    GpCryptoHash_Hmac::Res256T  serverKey           = GpCryptoHash_Hmac::S_256("Server Key"_sv, saltedPasswordCSP->ViewR().R());
    GpCryptoHash_Sha2::Res256T  storedKey           = GpCryptoHash_Sha2::S_256(clientKey);
    GpCryptoHash_Hmac::Res256T  clientSignature     = GpCryptoHash_Hmac::S_256(authMessage, storedKey);

    // Compute clientProof = iClientKey XOR clientSignature
    SmallContainerT clientProof;
    clientProof.resize(32);

    for (size_t id = 0; id < 4; id++)
    {
        const size_t    offset          = id * sizeof(u_int_64);
        const u_int_64  keyPart         = MemOps::SCopyBitCast<u_int_64>(std::data(clientKey) + offset);
        const u_int_64  signaturePart   = MemOps::SCopyBitCast<u_int_64>(std::data(clientSignature) + offset);
        const u_int_64  proofPart       = keyPart ^ signaturePart;

        std::memcpy(std::data(clientProof) + offset, &proofPart, sizeof(u_int_64));
    }

    return
    {
        clientKey,
        serverKey,
        authMessage,
        GpBytesArrayUtils::SMake<SmallContainerT>(clientFinalMessageWithoutProof),
        clientProof
    };
}

}// namespace GPlatform
