# ----------- Config -----------
TEMPLATE        = app
QMAKE_CXXFLAGS += -DGP_REFLECTION_STATIC_ADD_TO_MANAGER
QMAKE_CXXFLAGS += -DGP_MODULE_UUID=7d473551-7a9b-40ad-8744-1f236edc6e79
PACKET_NAME     = GpCryptoUtilsWasm
DEFINES		   += GP_CRYPTO_UTILS_WASM_LIBRARY
_VER_MAJ        = 2
_VER_MIN        = 1
_VER_PAT        = 6
DIR_LEVEL       = ./../..

include($$DIR_LEVEL/../QtGlobalPro.pri)

equals(var_link, "static") {
	CONFIG += staticlib
}

#------------------------------ LIBS BEGIN ---------------------------------
equals(var_os, "browser") {
	LIBS += -lGpCryptoUtils$$TARGET_POSTFIX
	LIBS += -lGpCryptoCore$$TARGET_POSTFIX
	LIBS += -lGpUtils$$TARGET_POSTFIX

	LIBS += -lsodium
	LIBS += -lutf8proc$$TARGET_POSTFIX

	QMAKE_LINK = sk
	QMAKE_LFLAGS += --action=exec --cmd_to_exec=em++ --filter_out_value=EXPORT_NAME* --filter_out_value=ASYNCIFY_IMPORTS* --filter_out_value=FETCH* --filter_out_value=MODULARIZE*
}
#------------------------------- LIBS END ----------------------------------

SOURCES += \
	SASL/Scram/GpCryptoSASLScramWasm.cpp

HEADERS += \
	GpCryptoUtilsWasm_global.hpp \
	SASL/Scram/GpCryptoSASLScramWasm.hpp
