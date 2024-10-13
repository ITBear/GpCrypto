# ----------- Config -----------
TEMPLATE        = lib
QMAKE_CXXFLAGS += -DGP_REFLECTION_STATIC_ADD_TO_MANAGER
QMAKE_CXXFLAGS += -DGP_MODULE_UUID=c49212af-d8cf-4210-8662-30d0b565738e
PACKET_NAME     = GpCryptoUtils
DEFINES        += GP_CRYPTO_UTILS_LIBRARY
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
	GpCryptoFileUtils.cpp \
	GpCryptoUtilsLib.cpp \
	SASL/Scram/GpCryptoSASLScram.cpp


HEADERS += \
	GpCryptoFileUtils.hpp \
	GpCryptoUtilsLib.hpp \
	GpCryptoUtils_global.hpp \
	SASL/Scram/GpCryptoSASLScram.hpp
