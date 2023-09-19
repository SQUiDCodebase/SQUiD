


find_package(benchmark REQUIRED)

add_library(GenomicPIR globals.hpp server.hpp server.cpp comparator.cpp comparator.hpp tools.cpp tools.hpp)
target_link_libraries(GenomicPIR helib)
target_link_libraries(GenomicPIR benchmark::benchmark)
#Add JSON package
include(FetchContent)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz)
FetchContent_MakeAvailable(json)
target_link_libraries(GenomicPIR nlohmann_json::nlohmann_json)

#Add CURL library
find_package(CURL REQUIRED)
target_link_libraries(GenomicPIR CURL::libcurl)

add_executable(main main.cpp)
add_executable(real real.cpp)
add_executable(squid SQUiD.cpp)

target_link_libraries(main GenomicPIR)
target_link_libraries(real GenomicPIR)
target_link_libraries(squid GenomicPIR)

install(TARGETS GenomicPIR
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  PUBLIC_HEADER DESTINATION include
)
