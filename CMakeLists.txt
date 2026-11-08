cmake_minimum_required(VERSION 3.21)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "Use an out-of-source build: cmake -S . -B .build/cmake")
endif()
if(NOT CMAKE_HOST_WIN32)
    message(FATAL_ERROR "WG-Win-Check requires Windows and the MSVC toolchain.")
endif()

project(WGWinCheck LANGUAGES CXX RC)

if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    message(FATAL_ERROR "Use MSVC v143 from Visual Studio 2022 or Build Tools 2022.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Only x64 is supported. Configure with -A x64.")
endif()
if(DEFINED CMAKE_VS_PLATFORM_NAME AND NOT CMAKE_VS_PLATFORM_NAME STREQUAL "x64")
    message(FATAL_ERROR "Only x64 is supported. Configure with -A x64.")
endif()

get_property(WGWC_MULTI_CONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(WGWC_MULTI_CONFIG)
    set(CMAKE_CONFIGURATION_TYPES "Debug;Release;ReleaseMT" CACHE STRING "Build configurations" FORCE)
else()
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE ReleaseMT CACHE STRING "Build configuration" FORCE)
    endif()
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release ReleaseMT)
    if(NOT CMAKE_BUILD_TYPE MATCHES "^(Debug|Release|ReleaseMT)$")
        message(FATAL_ERROR "Supported configurations: Debug, Release, ReleaseMT.")
    endif()
endif()

string(REPLACE "/O2" "/O1" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_RELEASEMT "${CMAKE_CXX_FLAGS_RELEASE}" CACHE STRING "ReleaseMT compiler flags")
set(CMAKE_EXE_LINKER_FLAGS_RELEASEMT "${CMAKE_EXE_LINKER_FLAGS_RELEASE}" CACHE STRING "ReleaseMT linker flags")
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<NOT:$<CONFIG:ReleaseMT>>:DLL>")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASEMT ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/$<CONFIG>")
set(CMAKE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/symbols/$<CONFIG>")

set(WGWC_CORE_SOURCES
    src/core/runtime/CollectionContext.cpp
    src/core/modules/network/NetworkModule.cpp
    src/core/modules/threat/ThreatSearch.h
    src/core/modules/threat/ThreatMatcher.cpp
    src/core/modules/threat/ThreatSearch.cpp
    src/core/modules/process/ProcessCollector.cpp
    src/core/modules/process/ProcessCollector.h
    src/core/model/CollectionIssue.h
    src/core/model/CollectionResult.h
    src/core/model/FileEvidence.h
    src/core/model/RiskFinding.h
    src/core/runtime/CollectionContext.h
    src/core/system/Win32.h
    src/core/modules/network/NetworkModule.h
    src/core/system/FileService.h
    src/core/system/FileService.cpp
    src/core/rules/RuleHelpers.h
    src/core/rules/RuleHelpers.cpp
    src/core/modules/process/ProcessRules.h
    src/core/modules/process/ProcessRules.cpp
    src/core/modules/process/ProcessModule.h
    src/core/modules/process/ProcessModule.cpp
    src/core/modules/user/UserModule.h
    src/core/modules/user/UserCollector.cpp
    src/core/modules/user/UserRules.cpp
    src/core/modules/autorun/AutorunModule.h
    src/core/modules/autorun/AutorunPaths.cpp
    src/core/modules/autorun/AutorunRules.cpp
    src/core/modules/autorun/AutorunCollector.cpp
    src/core/modules/autorun/AutorunWmi.cpp
    src/core/modules/service/ServiceModule.h
    src/core/modules/service/ServicePaths.cpp
    src/core/modules/service/ServiceRules.cpp
    src/core/modules/service/ServiceCollector.cpp
    src/core/modules/task/TaskModule.h
    src/core/modules/task/TaskPaths.cpp
    src/core/modules/task/TaskComResolver.cpp
    src/core/modules/task/TaskRules.cpp
    src/core/modules/task/TaskCollector.cpp
    src/core/system/IpLookupService.h
    src/core/system/IpLookupService.cpp
    src/core/system/IpLookupHttp.cpp
    src/core/modules/process/ProcessActions.h
    src/core/modules/service/ServiceActions.h
    src/core/modules/task/TaskActions.h
    src/shared/Constants.h
    src/core/modules/traces/TraceModule.cpp
    src/core/modules/filescan/FileScanModule.cpp
    src/core/modules/traces/TraceModule.h
    src/core/modules/filescan/FileScanModule.h
)

set(WGWC_GUI_SOURCES
    src/gui/presentation/GuiColumns.h
    src/gui/presentation/DisplayFormat.h
    src/gui/presentation/DisplayFormat.cpp
    src/gui/common/BackgroundTask.h
    src/gui/modules/traces/ActivityTraceInvestigator.h
    src/gui/modules/autorun/AutorunInvestigator.h
    src/gui/common/CommonUtils.h
    src/gui/common/ListViewSupport.h
    src/gui/app/ElevationPrompt.h
    src/gui/modules/event/EventInvestigator.h
    src/gui/modules/filescan/FileInvestigator.h
    src/gui/common/framework.h
    src/gui/common/IInvestigator.h
    src/gui/common/ListViewCsv.h
    src/gui/modules/network/IpLocationService.h
    src/gui/modules/network/NetworkInvestigator.h
    src/gui/modules/process/ProcessInvestigator.h
    src/gui/common/RiskOverviewItem.h
    src/gui/modules/risk/RiskOverviewInvestigator.h
    src/gui/common/RiskRepository.h
    src/gui/resources/resource.h
    src/gui/modules/service/ServiceInvestigator.h
    src/gui/common/targetver.h
    src/gui/modules/task/TaskInvestigator.h
    src/gui/modules/threat/ThreatSearchInvestigator.h
    src/gui/modules/user/UserInvestigator.h
    src/shared/Constants.h
    src/gui/app/WG-Win-Check.h
    src/gui/modules/traces/ActivityTraceInvestigator.cpp
    src/gui/modules/autorun/AutorunInvestigator.cpp
    src/gui/common/CommonUtils.cpp
    src/gui/common/ListViewSupport.cpp
    src/gui/app/ElevationPrompt.cpp
    src/gui/modules/event/EventInvestigator.cpp
    src/gui/modules/filescan/FileInvestigator.cpp
    src/gui/modules/network/IpLocationService.cpp
    src/gui/modules/network/NetworkInvestigator.cpp
    src/gui/modules/process/ProcessInvestigator.cpp
    src/gui/modules/risk/RiskOverviewInvestigator.cpp
    src/gui/common/RiskRepository.cpp
    src/gui/modules/service/ServiceInvestigator.cpp
    src/gui/modules/task/TaskInvestigator.cpp
    src/gui/modules/threat/ThreatSearchInvestigator.cpp
    src/gui/modules/user/UserInvestigator.cpp
    src/gui/app/WG-Win-Check.cpp
    src/gui/resources/WG-Win-Check.rc
    src/gui/resources/small.ico
    src/gui/resources/WG-Win-Check.ico
)

set(WGWC_CLI_SOURCES
    src/cli/CliVersion.rc
    src/cli/Main.cpp
    src/cli/CliApplication.cpp
    src/cli/output/Output.cpp
    src/cli/output/MachineResult.cpp
    src/cli/CliApplication.h
    src/cli/output/Output.h
    src/cli/output/MachineResult.h
    src/shared/Constants.h
)


add_library(WG-Win-Check-Core STATIC ${WGWC_CORE_SOURCES})
add_executable(WG-Win-Check WIN32 ${WGWC_GUI_SOURCES})
add_executable(WG-Win-Check-CLI ${WGWC_CLI_SOURCES})

foreach(target IN ITEMS WG-Win-Check-Core WG-Win-Check WG-Win-Check-CLI)
    target_compile_definitions(${target} PRIVATE UNICODE _UNICODE "$<$<CONFIG:Debug>:_DEBUG>")
    target_compile_options(${target} PRIVATE
        "$<$<COMPILE_LANGUAGE:CXX>:/utf-8>"
        "$<$<COMPILE_LANGUAGE:CXX>:/permissive->"
        "$<$<COMPILE_LANGUAGE:CXX>:/sdl>"
        "$<$<AND:$<COMPILE_LANGUAGE:CXX>,$<NOT:$<CONFIG:Debug>>>:/Os;/Gy;/GF;/Gw;/Oi>"
    )
endforeach()

target_compile_definitions(WG-Win-Check-Core PRIVATE _WIN32_WINNT=0x0A00)
target_compile_definitions(WG-Win-Check-CLI PRIVATE _WIN32_WINNT=0x0A00 _CONSOLE)
target_compile_definitions(WG-Win-Check PRIVATE _WINDOWS)
target_compile_options(WG-Win-Check-Core PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/W4>")
target_compile_options(WG-Win-Check-CLI PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/W4>")
target_compile_options(WG-Win-Check PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/W3>")

target_include_directories(WG-Win-Check PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/gui"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/gui/resources"
)

target_link_libraries(WG-Win-Check-Core PUBLIC
    advapi32 crypt32 iphlpapi netapi32 ole32 oleaut32 psapi shell32
    taskschd version wbemuuid wevtapi winhttp wintrust ws2_32
)
target_link_libraries(WG-Win-Check PRIVATE
    WG-Win-Check-Core comctl32 dbghelp ntdll shlwapi wininet
)
target_link_libraries(WG-Win-Check-CLI PRIVATE WG-Win-Check-Core)

foreach(target IN ITEMS WG-Win-Check WG-Win-Check-CLI)
    target_link_options(${target} PRIVATE
        "$<$<NOT:$<CONFIG:Debug>>:/INCREMENTAL:NO;/OPT:REF;/OPT:ICF>"
    )
endforeach()
