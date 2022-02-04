find_package(PkgConfig)
PKG_CHECK_MODULES(PC_DVBV5 dvbv5)

FIND_PATH(
    DVBV5_INCLUDE_DIRS
    NAMES libdvbv5/dvb-file.h
    HINTS ${PC_DVBV5_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    DVBV5_LIBRARIES
    NAMES dvbv5
    HINTS ${PC_DVBV5_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Dvbv5 DEFAULT_MSG DVBV5_LIBRARIES DVBV5_INCLUDE_DIRS)
MARK_AS_ADVANCED(DVBV5_LIBRARIES DVBV5_INCLUDE_DIRS)

