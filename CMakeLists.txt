CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
set(PLUGINS_DIR "${CMAKE_INSTALL_PREFIX}/${LIB_INSTALL_DIR}/sysrepo/plugins/" CACHE PATH "Sysrepo plugins directory.")


PROJECT(sysrepo-plugin-dt-network)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")

set(SOURCES
	src/network.c
  src/functions.c)

if(CMAKE_BUILD_TYPE MATCHES "test")
  add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
  install(TARGETS ${CMAKE_PROJECT_NAME}
	  DESTINATION lib/sysrepo/plugins)
else()
  add_library(${CMAKE_PROJECT_NAME} MODULE ${SOURCES})
  install(TARGETS ${CMAKE_PROJECT_NAME} LIBRARY
	  DESTINATION lib/sysrepo/plugins)
endif()

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES OUTPUT_NAME ${CMAKE_PROJECT_NAME} PREFIX "")

find_package(SYSREPO REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})

find_package(LIBNL REQUIRED)
find_package(LIBNL-NF REQUIRED)
find_package(LIBNL-ROUTE REQUIRED)
find_package(LIBNL-GENL REQUIRED)
include_directories(${LIBNL_INCLUDE_DIR})

install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION ${PLUGINS_DIR})
