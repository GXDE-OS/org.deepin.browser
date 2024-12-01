QT -= gui

CONFIG += c++11 console
CONFIG -= app_bundle
TARGET = deepin-password-auth

DISTFILES = com.deepin.pkexec.passwordAuth.policy
DESTDIR += $$PWD/out
SOURCES += \
        main.cpp

policy.path = /usr/share/polkit-1/actions
policy.files = $$PWD/com.deepin.pkexec.passwordAuth.policy
