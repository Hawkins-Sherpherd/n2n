project(n2n C)
cmake_minimum_required(VERSION 3.0)

# N2n information
set(N2N_VERSION 2.1.0)
set(N2N_OSNAME ${CMAKE_SYSTEM_NAME})

# N2n specific params
if(NOT DEFINED N2N_OPTION_AES)
set(N2N_OPTION_AES OFF)
endif(NOT DEFINED N2N_OPTION_AES)

add_definitions(-DN2N_VERSION=\"${N2N_VERSION}\" -DN2N_OSNAME=\"${N2N_OSNAME}\")

if(N2N_OPTION_AES)
add_definitions(-DN2N_HAVE_AES)
endif(N2N_OPTION_AES)

# Build information
if(NOT DEFINED BUILD_SHARED_LIBS)
set(BUILD_SHARED_LIBS OFF)
endif(NOT DEFINED BUILD_SHARED_LIBS)

if(NOT DEFINED CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE None)
endif(NOT DEFINED CMAKE_BUILD_TYPE)
#set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

#Ultrasparc64 users experiencing SIGBUS should try the following gcc options
#(thanks to Robert Gibbon) 
#PLATOPTS_SPARC64=-mcpu=ultrasparc -pipe -fomit-frame-pointer -ffast-math -finline-functions -fweb -frename-registers -mapp-regs

## DEBUG FOR CMAKE
#message(${N2N_VERSION}) 
#message(${N2N_OSNAME})
##message(${CMAKE_BUILD_TYPE})
#message(${N2N_OPTION_AES})
## DEBUG FOR CMAKE

add_library(n2n OBJECT
        n2n.c
        n2n_keyfile.c
        wire.c
        minilzo.c
        twofish.c
        transform_null.c
        transform_tf.c
        transform_aes.c
        tuntap_freebsd.c
        tuntap_netbsd.c
        tuntap_linux.c
        tuntap_osx.c
        version.c
)
set(OBJECTS $<TARGET_OBJECTS:n2n>)

if(DEFINED WIN32)

set(CMAKE_RC_FLAGS /nologo)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4477 /wd4267")

add_subdirectory(win32)
set(OBJECTS ${OBJECTS} $<TARGET_OBJECTS:n2n_win32>)
set(EDGE_RESOURCE ${CMAKE_CURRENT_SOURCE_DIR}/win32/edge.rc)
set(SN_RESOURCE ${CMAKE_CURRENT_SOURCE_DIR}/win32/sn.rc)

else(DEFINED WIN32)

set(EDGE_RESOURCE )
set(SN_RESOURCE )

endif(DEFINED WIN32)

if(N2N_OPTION_AES)
target_link_libraries(n2n crypto)
endif(N2N_OPTION_AES)

# For Solaris (or OpenSolaris?)
#target_link_libraries(n2n socket nsl)

add_executable(edge edge.c ${OBJECTS} ${EDGE_RESOURCE})
if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
target_link_libraries(edge cap)
endif()

add_executable(supernode sn.c ${OBJECTS} ${SN_RESOURCE})
if(DEFINED WIN32)
set_target_properties(edge PROPERTIES LINK_FLAGS "/manifestuac:level='requireAdministrator'")
add_custom_command(
        TARGET supernode
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/win32/install.ps1" "${CMAKE_CURRENT_BINARY_DIR}/install.ps1"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/win32/install.ps1"
)
endif(DEFINED WIN32)

if(NOT DEFINED WIN32)
#add_executable(test test.c)
#target_link_libraries(test n2n)

#add_executable(benchmark benchmark.c)
#target_link_libraries(benchmark n2n)
endif(NOT DEFINED WIN32)

install(TARGETS edge supernode
        RUNTIME DESTINATION sbin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)

# Documentation
if(DEFINED UNIX)
add_dependencies(n2n doc)
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/doc)
add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/doc/edge.8.gz
                   COMMAND gzip -c ${PROJECT_SOURCE_DIR}/edge.8 > ${PROJECT_BINARY_DIR}/doc/edge.8.gz
                   DEPENDS ${PROJECT_SOURCE_DIR}/edge.8
                  )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                   COMMAND gzip -c ${PROJECT_SOURCE_DIR}/supernode.1 > ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                   DEPENDS ${PROJECT_SOURCE_DIR}/supernode.1
                  )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
                   COMMAND gzip -c ${PROJECT_SOURCE_DIR}/n2n_v2.7 > ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
                   DEPENDS ${PROJECT_SOURCE_DIR}/n2n_v2.7
                  )

add_custom_target(doc DEPENDS ${PROJECT_BINARY_DIR}/doc/edge.8.gz
                              ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                              ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
                 )

set_source_files_properties(${PROJECT_BINARY_DIR}/doc/edge.8.gz
                            ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                            ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
                            PROPERTIES GENERATED 1)

install(FILES ${PROJECT_BINARY_DIR}/doc/edge.8.gz
        DESTINATION /usr/share/man8)
install(FILES ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
        DESTINATION /usr/share/man1)
install(FILES ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
        DESTINATION /usr/share/man7)
endif(DEFINED UNIX)
