# ----------- Config -----------
TEMPLATE        = lib
QMAKE_CXXFLAGS += -DGP_REFLECTION_STATIC_ADD_TO_MANAGER
QMAKE_CXXFLAGS += -DGP_MODULE_UUID=fdc6d09a-3103-4002-bb48-03483f3808a4
PACKET_NAME     = GpCryptoCore
DEFINES        += GP_CRYPTO_CORE_LIBRARY
_VER_MAJ        = 2
_VER_MIN        = 1
_VER_PAT        = 6
DIR_LEVEL       = ./../..

include($$DIR_LEVEL/../QtGlobalPro.pri)

release_build_static{
	CONFIG += staticlib
}

# ----------- Libraries -----------
os_windows{
}

os_linux{
	LIBS += -lutf8proc$$TARGET_POSTFIX
	LIBS += -lsodium
}

# ----------- Sources and headers -----------
SOURCES += \
	Encryption/GpEncryptionUtils_XChaCha20_Poly1305.cpp \
	ExtSources/ripemd160.cpp \
	GpCryptoCoreLib.cpp \
	Hashes/GpCryptoHash_Blake2b.cpp \
	Hashes/GpCryptoHash_Hmac.cpp \
	Hashes/GpCryptoHash_KDF_Passwd.cpp \
	Hashes/GpCryptoHash_PBKDF2.cpp \
	Hashes/GpCryptoHash_Ripemd160.cpp \
	Hashes/GpCryptoHash_Sha2.cpp \
	Keys/Curve25519/GpCryptoHDKeyGen_Ed25519.cpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_HD.cpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Import.cpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Rnd.cpp \
	Keys/Curve25519/GpCryptoKeyPair_Ed25519.cpp \
	Keys/Curve25519/GpCryptoKeyPair_X25519.cpp \
	Keys/GpCryptoKeyPair.cpp \
	Keys/GpCryptoKeyType.cpp \
	GpCryptoCore.cpp \
	Keys/HD/GpCryptoHDKeyGen.cpp \
	Keys/HD/GpCryptoHDKeyStorage.cpp \
	Keys/HD/GpCryptoHDSchemeType.cpp \
	MnemonicCodes/GpMnemonicCodeGen.cpp \
	Utils/GpByteWriterStorageSecure.cpp \
	Utils/GpCryptoRandom.cpp \
	Utils/GpSecureStorage.cpp \
	Utils/GpSecureStorageViewR.cpp \
	Utils/GpSecureStorageViewRW.cpp \
	Wallet/GpCryptoAddress.cpp \
	Wallet/GpCryptoAddressGroup.cpp \
	Wallet/GpCryptoWallet.cpp \
	Wallet/GpCryptoWalletUtils.cpp

HEADERS += \
	Encryption/GpEncryptionUtils_XChaCha20_Poly1305.hpp \
	ExtSources/ripemd160.hpp \
	GpCryptoCore.hpp \
	GpCryptoCoreLib.hpp \
	GpCryptoCore_global.hpp \
	Hashes/GpCryptoHash_Blake2b.hpp \
	Hashes/GpCryptoHash_Hmac.hpp \
	Hashes/GpCryptoHash_KDF_Passwd.hpp \
	Hashes/GpCryptoHash_PBKDF2.hpp \
	Hashes/GpCryptoHash_Ripemd160.hpp \
	Hashes/GpCryptoHash_Sha2.hpp \
	Keys/Curve25519/GpCryptoHDKeyGen_Ed25519.hpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_HD.hpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Import.hpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Rnd.hpp \
	Keys/Curve25519/GpCryptoKeyPair_Ed25519.hpp \
	Keys/Curve25519/GpCryptoKeyPair_X25519.hpp \
	Keys/GpCryptoKeyFactory.hpp \
	Keys/GpCryptoKeyPair.hpp \
	Keys/GpCryptoKeyType.hpp \
	Keys/HD/GpCryptoHDKeyGen.hpp \
	Keys/HD/GpCryptoHDKeyStorage.hpp \
	Keys/HD/GpCryptoHDSchemeType.hpp \
	MnemonicCodes/GpMnemonicCodeGen.hpp \
	Utils/GpByteWriterStorageSecure.hpp \
	Utils/GpCryptoRandom.hpp \
	Utils/GpSecureStorage.hpp \
	Utils/GpSecureStorageViewR.hpp \
	Utils/GpSecureStorageViewRW.hpp \
	Wallet/GpCryptoAddress.hpp \
	Wallet/GpCryptoAddressFactory.hpp \
	Wallet/GpCryptoAddressGroup.hpp \
	Wallet/GpCryptoWallet.hpp \
	Wallet/GpCryptoWalletUtils.hpp
