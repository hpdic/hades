cmake_minimum_required(VERSION 3.10)
project(HADES)

# 包含路径
include_directories(/home/cc/openfhe-development/src/pke/include/)
include_directories(/home/cc/openfhe-development/src/core/include/)
include_directories(/home/cc/openfhe-development/src/binfhe/include/)
include_directories(/home/cc/openfhe-development/build/include/)
include_directories(/home/cc/openfhe-development/build/src/core)
include_directories(/home/cc/openfhe-development/third-party/cereal/include/)

# 链接库路径
link_directories(/home/cc/openfhe-development/build/lib/)

# 可执行文件
add_executable(hades hades.cpp)

# 链接到 OpenFHE 的核心库
target_link_libraries(hades
    OPENFHEcore
    OPENFHEpke
    OPENFHEbinfhe
)
