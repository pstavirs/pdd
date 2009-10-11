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

QMAKE_EXTRA_TARGETS += revtarget
PRE_TARGETDEPS      += version.h
revtarget.target     = version.h
win32:revtarget.commands   = @echo "const char *version = \"0.1\";" \
	"const char *revision = \"$(shell svnversion .)\";" > $$revtarget.target
unix:revtarget.commands = @echo "\"const char *version = \\\"0.1\\\";" \
	"const char *revision = \\\"$(shell svnversion .)\\\";\"" > $$revtarget.target

revtarget.depends = $$SOURCES $$HEADERS $$FORMS

