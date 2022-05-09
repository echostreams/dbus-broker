cmake_minimum_required (VERSION 3.8)

set (CMAKE_CXX_STANDARD 11)

if(WIN32)
	message(STATUS "PATH: $ENV{PATH}")
    if(DEFINED ENV{VCPKG_ROOT})
	    message(STATUS "VCPKG_ROOT: $ENV{VCPKG_ROOT}")
	    file(TO_CMAKE_PATH $ENV{VCPKG_ROOT} VCPKG_LOCAL_ROOT)
	    message(STATUS "VCPKG_LOCAL_ROOT: ${VCPKG_LOCAL_ROOT}")
	    message(STATUS "CMAKE_TOOLCHAIN_FILE: ${CMAKE_TOOLCHAIN_FILE}")
	    if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
		    #set(CMAKE_TOOLCHAIN_FILE "${VCPKG_LOCAL_ROOT}/scripts/buildsystems/vcpkg.cmake"
		    #	CACHE STRING "")
	    endif()
	    message(STATUS "CMAKE_TOOLCHAIN_FILE: ${CMAKE_TOOLCHAIN_FILE}")
	endif()
	# try clang on windows
	# Must be called before project call
	if(EXISTS "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin/clang-cl.exe")
		set(LLVM_PATH "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin")
	elseif(EXISTS "C:/Program Files (x86)/Microsoft Visual Studio/2019/Enterprise/VC/Tools/Llvm/x64/bin/clang-cl.exe")
		set(LLVM_PATH "C:/Program Files (x86)/Microsoft Visual Studio/2019/Enterprise/VC/Tools/Llvm/x64/bin")
	endif()
	set(CMAKE_C_COMPILER "${LLVM_PATH}/clang-cl.exe")
    set(CMAKE_CXX_COMPILER "${LLVM_PATH}/clang-cl.exe") 
	set(CMAKE_LINKER "${LLVM_PATH}/lld-link.exe")
    #set(CMAKE_C_COMPILER_ID "Clang") 
    #set(CMAKE_CXX_COMPILER_ID "Clang") 
	
else()
	

endif()

project(dbus-broker)

if(WIN32)
    include(TestBigEndian)
    TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
    add_definitions(-DLITTLE_ENDIAN=1234)
    add_definitions(-DBIG_ENDIAN=4321)
    if(IS_BIG_ENDIAN)
        message(STATUS "BIG_ENDIAN")
        add_definitions(-DBYTE_ORDER=BIG_ENDIAN)
    else()
        message(STATUS "LITTLE_ENDIAN")
        add_definitions(-DBYTE_ORDER=LITTLE_ENDIAN)
    endif()

    check_type_size("long" __SIZEOF_LONG__)
    message(STATUS "__SIZEOF_LONG__: ${__SIZEOF_LONG__}")
    add_definitions(-D__SIZEOF_LONG__=${__SIZEOF_LONG__})
    
    include_directories(windows/posix/include)
    include_directories(windows)

else()
    add_definitions(-D_GNU_SOURCE)

    # detect WSL
	#CMAKE_SYSTEM_NAME:      Linux
	#CMAKE_SYSTEM:           Linux-4.4.0-19041-Microsoft
    message(STATUS "CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
	if(CMAKE_SYSTEM_NAME MATCHES "Linux")
		string(FIND ${CMAKE_SYSTEM} "Microsoft" WSL)
        message(STATUS "WSL: ${WSL}")
		if(WSL EQUAL -1)
			remove_definitions(-DWSL2)
		else()
			add_definitions(-DWSL2)
		endif()
	
	endif()
endif()



add_definitions(-DPACKAGE_VERSION=29)

include_directories(src)
include_directories(dep/c-stdaux/src)
include_directories(dep/c-rbtree/src)
include_directories(dep/c-list/src)
include_directories(dep/c-dvar/src)
include_directories(dep/c-utf8/src)

add_library(libcdvar
                "dep/c-dvar/src/c-dvar.c"
                "dep/c-dvar/src/c-dvar-common.c"
                "dep/c-dvar/src/c-dvar-reader.c"
                "dep/c-dvar/src/c-dvar-type.c"
                "dep/c-dvar/src/c-dvar-writer.c"
)
add_library(libcrbtree
    "dep/c-rbtree/src/c-rbtree.c"
)
add_library(libcutf8
    "dep/c-utf8/src/c-utf8.c"
)
set(sources_bus
        "src/broker/broker.c"
        "src/broker/controller.c"
        "src/broker/controller-dbus.c"
        "src/bus/activation.c"
        "src/bus/bus.c"
        "src/bus/driver.c"
        "src/bus/listener.c"
        "src/bus/match.c"
        "src/bus/name.c"
        "src/bus/peer.c"
        "src/bus/policy.c"
        "src/bus/reply.c"
        "src/dbus/address.c"
        "src/dbus/connection.c"
        "src/dbus/message.c"
        "src/dbus/protocol.c"
        "src/dbus/queue.c"
        "src/dbus/sasl.c"
        "src/dbus/socket.c"
        "src/util/apparmor.c"
        "src/util/error.c"
        "src/util/dirwatch.c"
        "src/util/dispatch.c"
        "src/util/fdlist.c"
        "src/util/log.c"
        "src/util/metrics.c"
        "src/util/misc.c"
        "src/util/proc.c"
        "src/util/sockopt.c"
        "src/util/string.c"
        "src/util/systemd.c"
        "src/util/user.c"
)

if(USE_AUDIT)
    list(APPEND sources_bus
        "src/util/audit.c"
    )
else()
    list(APPEND sources_bus
        "src/util/audit-fallback.c"
    )
endif()

if(USE_SELINUX)
    list(APPEND sources_bus
        "src/util/selinux.c"
    )
else()
    list(APPEND sources_bus
        "src/util/selinux-fallback.c"
    )
endif()

if(WIN32)
    list(APPEND sources_bus
        "windows/getopt.c"
        "windows/getopt_long.c"
        "windows/wepoll/wepoll.c"
        "windows/win_clock_gettime.c"
        "windows/mmap.c"
        "windows/strndup.c"
    )
endif()

add_library(libbus
	${sources_bus}
)

if(NOT WIN32)
    target_compile_options(libbus PRIVATE -fvisibility=hidden -fno-common)
endif()

add_executable(dbus-broker
	"src/broker/main.c"
)

target_link_libraries(dbus-broker libbus libcdvar libcrbtree libcutf8)

if(WIN32)
    add_executable(getuid "windows/getuid.cpp")
    target_compile_definitions(getuid PRIVATE -DGETUID_TEST)
    target_link_libraries(getuid libbus libcdvar libcrbtree libcutf8)
    target_link_libraries(dbus-broker ws2_32)
else()
    target_link_libraries(dbus-broker m)
endif()


add_executable(test-broker
    "test/dbus/test-broker.c"
    "test/dbus/util-broker.c"
)

target_link_libraries(test-broker pthread systemd)


add_executable(dbus-launch
    "test/dbus/dbus-launch.c"
    "test/dbus/util-broker.c"
)

target_link_libraries(dbus-launch pthread systemd)
