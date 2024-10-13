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

equals(var_link, "static") {
	CONFIG += staticlib
}

# ----------- Libraries -----------
equals(var_os, "windows") {
	LIBS += -lGpUtils$$TARGET_POSTFIX

	LIBS += -lutf8proc$$TARGET_POSTFIX
	LIBS += -llibsodium
}

equals(var_os, "linux") {
	LIBS += -lGpUtils$$TARGET_POSTFIX

	LIBS += -lutf8proc$$TARGET_POSTFIX
	LIBS += -lsodium
	LIBS += -lfmt
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
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_FromSeed.cpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_HD.cpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Rnd.cpp \
	Keys/Curve25519/GpCryptoKeyFactory_X25519_FromSeed.cpp \
	Keys/Curve25519/GpCryptoKeyFactory_X25519_Rnd.cpp \
	Keys/Curve25519/GpCryptoKeyPair_Ed25519.cpp \
	Keys/Curve25519/GpCryptoKeyPair_X25519.cpp \
	GpCryptoCore.cpp \
	Keys/GpCryptoEncryptKeyPair.cpp \
	Keys/GpCryptoEncryptKeyType.cpp \
	Keys/GpCryptoKeyPair.cpp \
	Keys/GpCryptoSignKeyPair.cpp \
	Keys/GpCryptoSignKeyType.cpp \
	Keys/HD/GpCryptoHDKeyGen.cpp \
	Keys/HD/GpCryptoHDKeyStorage.cpp \
	Keys/HD/GpCryptoHDSchemeType.cpp \
	MnemonicCodes/GpCryptoMnemonicUtils.cpp \
	Utils/GpByteWriterStorageSecure.cpp \
	Utils/GpCryptoRandom.cpp \
	Utils/GpSecureStorage.cpp \
	Utils/GpSecureStorageViewR.cpp \
	Utils/GpSecureStorageViewRW.cpp

HEADERS += \
	../Config/GpConfigCrypto.hpp \
	../Config/GpConfigCrypto_os_android.hpp \
	../Config/GpConfigCrypto_os_baremetal.hpp \
	../Config/GpConfigCrypto_os_browser.hpp \
	../Config/GpConfigCrypto_os_ios.hpp \
	../Config/GpConfigCrypto_os_ios_simulator.hpp \
	../Config/GpConfigCrypto_os_linux.hpp \
	../Config/GpConfigCrypto_os_macosx.hpp \
	../Config/GpConfigCrypto_os_windows.hpp \
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
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_FromSeed.hpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_HD.hpp \
	Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Rnd.hpp \
	Keys/Curve25519/GpCryptoKeyFactory_X25519_FromSeed.hpp \
	Keys/Curve25519/GpCryptoKeyFactory_X25519_Rnd.hpp \
	Keys/Curve25519/GpCryptoKeyPair_Ed25519.hpp \
	Keys/Curve25519/GpCryptoKeyPair_X25519.hpp \
	Keys/GpCryptoEncryptKeyFactory.hpp \
	Keys/GpCryptoEncryptKeyPair.hpp \
	Keys/GpCryptoEncryptKeyType.hpp \
	Keys/GpCryptoKeyPair.hpp \
	Keys/GpCryptoSignKeyFactory.hpp \
	Keys/GpCryptoSignKeyPair.hpp \
	Keys/GpCryptoSignKeyType.hpp \
	Keys/HD/GpCryptoHDKeyGen.hpp \
	Keys/HD/GpCryptoHDKeyStorage.hpp \
	Keys/HD/GpCryptoHDSchemeType.hpp \
	MnemonicCodes/GpCryptoMnemonicUtils.hpp \
	Utils/GpByteWriterStorageSecure.hpp \
	Utils/GpCryptoRandom.hpp \
	Utils/GpSecureStorage.hpp \
	Utils/GpSecureStorageViewR.hpp \
	Utils/GpSecureStorageViewRW.hpp
