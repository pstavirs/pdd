TEMPLATE = app
QT += xml
RC_FILE = pdd.rc
RESOURCES = pdd.qrc
FORMS = \
	hexdumpedit.ui \
	pktdumpdecode.ui \
	settings.ui

HEADERS = \
	hexdumpedit.h \
	pktdumpdecode.h \
	pdmlhandler.h \
	psmlhandler.h \
	settings.h 

SOURCES = \
	hexdumpedit.cpp \
	pktdumpdecode.cpp \
	pdmlhandler.cpp \
	psmlhandler.cpp \
	main.cpp \
	settings.cpp

include (version.pri)

