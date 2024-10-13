# ----------- Config -----------
TEMPLATE        = lib
QMAKE_CXXFLAGS += -DGP_REFLECTION_STATIC_ADD_TO_MANAGER
QMAKE_CXXFLAGS += -DGP_MODULE_UUID=1bdc14b8-a4a6-41ad-4f20-29d3a73d06d9
PACKET_NAME     = GpCryptoWallet
DEFINES        += GP_CRYPTO_WALLET_LIBRARY
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
	LIBS += -lGpCryptoCore$$TARGET_POSTFIX
	LIBS += -lGpUtils$$TARGET_POSTFIX
}

equals(var_os, "linux") {
	LIBS += -lGpCryptoCore$$TARGET_POSTFIX
	LIBS += -lGpUtils$$TARGET_POSTFIX

	LIBS += -lfmt
}

# ----------- Sources and headers -----------
SOURCES += \
	GpCryptoWallet.cpp \
	GpCryptoWalletAddress.cpp \
	GpCryptoWalletAddressGroup.cpp \
	GpCryptoWalletLib.cpp \
	GpCryptoWalletUtils.cpp


HEADERS += \
	GpCryptoWallet.hpp \
	GpCryptoWalletAddress.hpp \
	GpCryptoWalletAddressFactory.hpp \
	GpCryptoWalletAddressGroup.hpp \
	GpCryptoWalletLib.hpp \
	GpCryptoWalletUtils.hpp \
	GpCryptoWallet_global.hpp

