CC          = cl
LINK        = link

TARGETNAME  = socksifier
ARCH        = $(VSCMD_ARG_TGT_ARCH)
TOOLSET     = v141 # v90, v100, v110, v120, v140, v141
RUNTIME     = mt   # mt, mtd, md, mdd
VERSION     = $(ARCH)-$(TOOLSET)-$(RUNTIME)
TARGET      = $(TARGETNAME)-$(VERSION)
CFLAGS      = /Wall

SRCDIR      = src
INCDIR      = inc
LIBDIR      = lib
BUILDDIR    = obj
TARGETDIR   = bin

MINHOOK     = libMinHook-$(VERSION).lib

!IF "$(RUNTIME)" == "mt"
CFLAGS = $(CFLAGS) /MT
!ELSE IF "$(RUNTIME)" == "mtd"
CFLAGS = $(CFLAGS) /MTd
!ELSE IF "$(RUNTIME)" == "md"
CFLAGS = $(CFLAGS) /MDd
!ELSE IF "$(RUNTIME)" == "mdd"
CFLAGS = $(CFLAGS) /MDd
!ENDIF

all: directories $(TARGET) clean_for_distrib

directories: build_directory target_directory

build_directory:
    if not exist $(BUILDDIR)\$(ARCH)\$(TOOLSET)\$(RUNTIME) mkdir $(BUILDDIR)\$(ARCH)\$(TOOLSET)\$(RUNTIME)

target_directory:
    if not exist $(TARGETDIR) mkdir $(TARGETDIR)

clean:
    if exist $(BUILDDIR) rmdir /s /q $(BUILDDIR)
    if exist $(TARGETDIR) rmdir /s /q $(TARGETDIR)

clean_for_distrib: $(TARGET)
    del $(TARGETDIR)\$(TARGET).lib
    del $(TARGETDIR)\$(TARGET).exp

{$(SRCDIR)\}.c{$(BUILDDIR)\$(ARCH)\$(TOOLSET)\$(RUNTIME)}.obj:
    $(CC) /c $(CFLAGS) $** /I $(INCDIR) /D_USRDLL /D_WINDLL /Fo$@

$(TARGET): $(BUILDDIR)\$(ARCH)\$(TOOLSET)\$(RUNTIME)\$(TARGETNAME).obj $(LIBDIR)\$(MINHOOK)
    $(LINK) $** /LTCG /DLL /OUT:$(TARGETDIR)\$@.dll
