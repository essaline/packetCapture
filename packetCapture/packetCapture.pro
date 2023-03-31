QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    datapackage.cpp \
    main.cpp \
    mainwindow.cpp \
    multithread.cpp

HEADERS += \
    datapackage.h \
    format.h \
    mainwindow.h \
    multithread.h

#头文件引用
INCLUDEPATH += E:/networkProtocolAnalysis/winpcap/WpdPack/WpdPack/Include

#库文件引用
#LIBS += E:/networkProtocolAnalysis/winpcap/WpdPack/WpdPack/Lib/wpcap.lib  libws2_32
LIBS+=libws2_32
FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    qss.qrc \
    resource.qrc

unix|win32: LIBS += -L$$PWD/../winpcap/WpdPack/WpdPack/Lib/ -lwpcap

INCLUDEPATH += $$PWD/../winpcap/WpdPack/WpdPack/Lib
DEPENDPATH += $$PWD/../winpcap/WpdPack/WpdPack/Lib

win32:!win32-g++: PRE_TARGETDEPS += $$PWD/../winpcap/WpdPack/WpdPack/Lib/wpcap.lib
else:unix|win32-g++: PRE_TARGETDEPS += $$PWD/../winpcap/WpdPack/WpdPack/Lib/libwpcap.a
