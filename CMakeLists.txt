cmake_minimum_required (VERSION 3.8)



if(WIN32)
	message(STATUS "PATH: $ENV{PATH}")
    if(DEFINED ENV{VCPKG_ROOT})
	    message(STATUS "VCPKG_ROOT: $ENV{VCPKG_ROOT}")
	    file(TO_CMAKE_PATH $ENV{VCPKG_ROOT} VCPKG_LOCAL_ROOT)
	    message(STATUS "VCPKG_LOCAL_ROOT: ${VCPKG_LOCAL_ROOT}")
	    message(STATUS "CMAKE_TOOLCHAIN_FILE: ${CMAKE_TOOLCHAIN_FILE}")
	    if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
		    set(CMAKE_TOOLCHAIN_FILE "${VCPKG_LOCAL_ROOT}/scripts/buildsystems/vcpkg.cmake"
		    	CACHE STRING "")
	    endif()
	    message(STATUS "CMAKE_TOOLCHAIN_FILE: ${CMAKE_TOOLCHAIN_FILE}")
	endif()
	# using clang on windows
	# Must be called before project call
    message(STATUS "VCINSTALLDIR: $ENV{VCINSTALLDIR}")
    if(DEFINED ENV{VCINSTALLDIR})
        file(TO_CMAKE_PATH $ENV{VCINSTALLDIR} VC_INSTALL_DIR)
	    if(EXISTS "${VC_INSTALL_DIR}/Tools/Llvm/x64/bin/clang-cl.exe")
		    set(LLVM_PATH "${VC_INSTALL_DIR}/Tools/Llvm/x64/bin")
	    endif()
	    set(CMAKE_C_COMPILER "${LLVM_PATH}/clang-cl.exe")
        set(CMAKE_CXX_COMPILER "${LLVM_PATH}/clang-cl.exe") 
	    set(CMAKE_LINKER "${LLVM_PATH}/lld-link.exe")
	endif()
else()
	

endif()

project(dbus-broker)
set (CMAKE_CXX_STANDARD 11)

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
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
    add_definitions(-D_GNU_SOURCE)
	add_definitions(-DHAVE_REALLOCARRAY)
	add_definitions(-DHAVE_NAME_TO_HANDLE_AT)
	add_definitions(-DWANT_LINUX_STAT_H)
	add_definitions(-DHAVE_STRUCT_STATX)

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

include_directories(BEFORE systemd/src)

include_directories(
	"systemd/src/systemd"
	"systemd/src/libsystemd/sd-bus"
	"systemd/src/libsystemd/sd-id128"
	"systemd/src/libsystemd/sd-event"
	"systemd/src/basic"
	"systemd/src/fundamental"
	"systemd/src/shared"
)

if(WIN32)
	add_definitions(-DRELATIVE_SOURCE_PATH="..\\\\..\\\\..\\\\systemd\\\\src")
else()
	#add_definitions(-DRELATIVE_SOURCE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/systemd/src")
	add_definitions(-DRELATIVE_SOURCE_PATH="../../../systemd/src")
endif()
add_definitions(-DGETTEXT_PACKAGE="systemd")
add_definitions(-DNOBODY_USER_NAME="nobody")
add_definitions(-DNOBODY_GROUP_NAME="nogroup")
add_definitions(-DNOLOGIN="/usr/sbin/nologin")
add_definitions(-DFALLBACK_HOSTNAME="buildroot")
add_definitions(-DDEFAULT_HIERARCHY_NAME="hybrid")
add_definitions(-DSYSTEMD_TEST_DATA="./testdata")
add_definitions(-DSYSTEMD_CATALOG_DIR="./catalog")
add_definitions(-DSYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH="/bin/systemd-tty-ask-password-agent")
add_definitions(-DSYSTEMD_SLOW_TESTS_DEFAULT=0)
add_definitions(-DBUILD_MODE_DEVELOPER)
add_definitions(-DSIZEOF_TIME_T=8)
add_definitions(-DSIZEOF_TIMEX_MEMBER=8)
add_definitions(-DSIZEOF_RLIM_T=8)
add_definitions(-DSIZEOF_DEV_T=8)
add_definitions(-DSIZEOF_INO_T=8)
add_definitions(-D_FILE_OFFSET_BITS=64)
add_definitions(-DGPERF_LEN_TYPE=size_t)

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

add_library(libsystemd-mini 
	"systemd/src/libsystemd/sd-bus/bus-objects.c"
	"systemd/src/libsystemd/sd-bus/bus-type.c"
	"systemd/src/libsystemd/sd-bus/bus-internal.c"
	"systemd/src/libsystemd/sd-bus/bus-slot.c"
	"systemd/src/libsystemd/sd-bus/bus-error.c"
	"systemd/src/libsystemd/sd-bus/bus-introspect.c"
	"systemd/src/libsystemd/sd-bus/bus-signature.c"
	"systemd/src/libsystemd/sd-bus/bus-match.c"
	"systemd/src/libsystemd/sd-bus/bus-gvariant.c"
	"systemd/src/libsystemd/sd-bus/bus-convenience.c"
	"systemd/src/libsystemd/sd-bus/bus-kernel.c"
	"systemd/src/libsystemd/sd-bus/bus-control.c"
	#"systemd/src/libsystemd/sd-bus/bus-message.c"
	#"systemd/src/libsystemd/sd-bus/sd-bus.c"
	"systemd/src/libsystemd/sd-bus/bus-dump.c"
	"systemd/src/libsystemd/sd-bus/bus-socket.c"
	"systemd/src/libsystemd/sd-bus/bus-creds.c"
	"systemd/src/libsystemd/sd-bus/bus-track.c"

	"mini/bus-message.c"
	"mini/sd-bus.c"
	"mini/sd-event.c"
	"mini/hashmap.c"
	"mini/fileio.c"
	"mini/path-util.c"
	"mini/log.c"
	"mini/strv.c"
	"mini/randombytes.c"
	"mini/escape.c"
	"mini/string-util.c"
	"mini/time-util.c"
	"mini/locale-util.c"
	"mini/tests.c"
	"mini/fd-util.c"
	"mini/fs-util.c"
	"mini/socket-util.c"
	"mini/user-util.c"
	"mini/process-util.c"

	"systemd/src/basic/errno-list.c"
	"systemd/src/basic/ordered-set.c"
	"systemd/src/basic/siphash24.c"
	"systemd/src/basic/hash-funcs.c"
	"systemd/src/basic/memory-util.c"
	"systemd/src/basic/alloc-util.c"
	"systemd/src/fundamental/string-util-fundamental.c"
	"systemd/src/fundamental/sha256.c"
	"systemd/src/shared/xml.c"
	"systemd/src/basic/hmac.c"
	"systemd/src/basic/glyph-util.c"
	"systemd/src/basic/bus-label.c"
	"systemd/src/basic/utf8.c"
	"systemd/src/basic/gunicode.c"
	"systemd/src/basic/prioq.c"
	"systemd/src/basic/mempool.c"
	"systemd/src/basic/io-util.c"
	"systemd/src/basic/hexdecoct.c"
	"systemd/src/basic/parse-util.c"
	#"systemd/src/basic/socket-util.c"
	#"systemd/src/shared/tests.c"
	"systemd/src/shared/bus-object.c"
	"systemd/src/shared/bus-print-properties.c"
	#"systemd/src/shared/varlink.c"
	"systemd/src/basic/extract-word.c"
	"systemd/src/basic/strxcpyx.c"
	"systemd/src/basic/ratelimit.c"
	"systemd/src/basic/signal-util.c"
	"systemd/src/basic/string-table.c"

	"windows/asprintf.c"
	"windows/strndup.c"
	"windows/getuid.cpp"
	"windows/mmap.c"
	"windows/win_clock_gettime.c"
	"windows/socket.c"
	"windows/posix.c"
	"windows/wepoll/wepoll.c"
	"windows/poll.c"
	"windows/compat.c"
	"windows/dump_wsaprotocol_info.c"

	"systemd/src/busctl/busctl-introspect.c"

	#"systemd/src/libsystemd/sd-event/sd-event.c"
	"systemd/src/libsystemd/sd-daemon/sd-daemon.c"
	"systemd/src/libsystemd/sd-id128/sd-id128.c"
	"systemd/src/libsystemd/sd-id128/id128-util.c"
)

add_executable(dbus-broker
	"src/broker/main.c"
)

target_link_libraries(dbus-broker libbus libcdvar libcrbtree libcutf8)

if(WIN32)
    add_executable(getuid "windows/getuid.cpp")
    target_compile_definitions(getuid PRIVATE -DGETUID_TEST)
    target_link_libraries(getuid libbus libcdvar libcrbtree libcutf8 ws2_32 iphlpapi Netapi32)
    target_link_libraries(dbus-broker ws2_32 iphlpapi libsystemd-mini)
else()
    target_link_libraries(dbus-broker m)
endif()


if(WIN32)

	add_executable(dbus-launch
		"test/dbus/dbus-launch-win.c"
		"test/dbus/util-broker-win.c"
	)
	add_executable(test-broker
		"test/dbus/test-broker-win.c"
		"test/dbus/util-broker-win.c"
	)
	add_executable(test-dispatch
		"src/util/test-dispatch-win.c"
	)	
	target_link_libraries(dbus-launch libsystemd-mini ws2_32 iphlpapi)
	target_link_libraries(test-broker libsystemd-mini ws2_32 iphlpapi)

else()

	add_executable(dbus-launch
		"test/dbus/dbus-launch.c"
		"test/dbus/util-broker.c"
	)
	add_executable(test-broker
		"test/dbus/test-broker.c"
		"test/dbus/util-broker.c"
	)
	add_executable(test-dispatch
		"src/util/test-dispatch.c"
	)	
	target_link_libraries(dbus-launch libsystemd-mini pthread)
	target_link_libraries(test-broker libsystemd-mini pthread)

endif()

target_link_libraries(test-dispatch libbus uv_a)

add_subdirectory("libuv-1.44.1")

add_executable(tcp-echo
	"test/tcp-echo.c"
)

target_link_libraries(tcp-echo uv_a)

add_executable(test-socket
	"src/dbus/test-socket.c"
)
target_link_libraries(test-socket libbus libcdvar libcrbtree libcutf8)
if(WIN32)
	target_link_libraries(test-socket libsystemd-mini ws2_32)
endif()

add_executable(test-user
	"src/util/test-user.c"
)
target_link_libraries(test-user libbus libcdvar libcrbtree libcutf8)
if(WIN32)
	target_link_libraries(test-user ws2_32)
endif()

add_executable(uv-bus
	"test/uv-bus.cpp"
)
target_link_libraries(uv-bus uv_a libsystemd-mini)

add_executable(sd-event-udp
	"test/sd-event-udp.c"
)
target_link_libraries(sd-event-udp libsystemd-mini)
if(WIN32)
	target_link_libraries(sd-event-udp ws2_32 iphlpapi)
else()
	target_link_libraries(sd-event-udp pthread)
endif()