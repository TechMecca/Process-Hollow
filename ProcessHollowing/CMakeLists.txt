add_library(ProcessHollowing STATIC)

target_sources(ProcessHollowing PUBLIC
    "src/ProcessHollowing.cpp"
    "src/patch_ntdll.cpp"
)

target_include_directories(ProcessHollowing PUBLIC
    "include"
)

add_library(ProcessHollowing::ProcessHollowing ALIAS ProcessHollowing)
