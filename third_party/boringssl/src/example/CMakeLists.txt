include_directories(../include)

add_executable(
  client

  client.cpp
)

add_dependencies(client global_target)

if(APPLE OR WIN32 OR ANDROID)
  target_link_libraries(client ssl crypto)
else()
  find_library(FOUND_LIBRT rt)
  if(FOUND_LIBRT)
    target_link_libraries(client ssl crypto -lrt -lpthread dl)
  else()
    target_link_libraries(client ssl crypto -lpthread dl)
  endif()
endif()

add_executable(
  server
  server.cpp
)

add_dependencies(server global_target)

if(APPLE OR WIN32 OR ANDROID)
  target_link_libraries(server ssl crypto)
else()
  find_library(FOUND_LIBRT rt)
  if(FOUND_LIBRT)
    target_link_libraries(server ssl crypto -lrt -lpthread dl)
  else()
    target_link_libraries(server ssl crypto -lpthread dl)
  endif()
endif()