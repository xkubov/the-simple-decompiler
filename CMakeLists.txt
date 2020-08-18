cmake_minimum_required(VERSION 3.12)

find_package(PkgConfig REQUIRED)

project(retdec-plugin-example C CXX)

set(Radare2_CMAKE_PREFIX_PATH_TEMP ${CMAKE_PREFIX_PATH})
list(APPEND CMAKE_PREFIX_PATH
	"$ENV{HOME}/bin/prefix/radare2"
	"/usr/local"
)

pkg_search_module(Radare2 IMPORTED_TARGET REQUIRED r_core)

set(CMAKE_PREFIX_PATH ${Radare2_CMAKE_PREFIX_PATH_TEMP})
mark_as_advanced(Radare2_CMAKE_PREFIX_PATH_TEMP)

if(TARGET PkgConfig::Radare2)
	set_target_properties(PkgConfig::Radare2 PROPERTIES IMPORTED_GLOBAL ON)
	add_library(Radare2::libr ALIAS PkgConfig::Radare2)
	set(Radare2_TARGET Radare2::libr)
else()
	set(Radare2_TARGET Radare2_TARGET-NOTFOUND)
endif()

find_package(retdec 4.0 REQUIRED COMPONENTS retdec config)

add_library(simple_decompiler SHARED
	src/simple_decompiler.cpp
	src/r2cgen.cpp
)

target_link_libraries(simple_decompiler
	retdec::retdec
	retdec::config
	Radare2::libr
)


if (APPLE)
	target_link_libraries(simple_decompiler
		-Wl,-force_load retdec::bin2llvmir
		-Wl,-force_load retdec::llvmir2hll
	)
else ()
	target_link_libraries(simple_decompiler
		-Wl,--whole-archive retdec::bin2llvmir -Wl,--no-whole-archive
		-Wl,--whole-archive retdec::llvmir2hll -Wl,--no-whole-archive
	)
endif()

set_target_properties(simple_decompiler PROPERTIES
	OUTPUT_NAME simple_decompiler
	PREFIX ""
)

set(RADARE2_INSTALL_PLUGDIR
	"share/radare2/plugins" CACHE PATH
	"Directory to install radare2 plugin into"
)

add_subdirectory(support)

install(TARGETS simple_decompiler DESTINATION "${RADARE2_INSTALL_PLUGDIR}")
