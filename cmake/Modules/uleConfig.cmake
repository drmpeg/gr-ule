INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_ULE ule)

FIND_PATH(
    ULE_INCLUDE_DIRS
    NAMES ule/api.h
    HINTS $ENV{ULE_DIR}/include
        ${PC_ULE_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    ULE_LIBRARIES
    NAMES gnuradio-ule
    HINTS $ENV{ULE_DIR}/lib
        ${PC_ULE_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(ULE DEFAULT_MSG ULE_LIBRARIES ULE_INCLUDE_DIRS)
MARK_AS_ADVANCED(ULE_LIBRARIES ULE_INCLUDE_DIRS)

