cmake_minimum_required(VERSION 3.20)
project(aegis-kernel LANGUAGES C CXX)

# ── Kernel driver (mini-filter + object callbacks) ───────────────────────────
# Builds with the Windows Driver Kit (WDK). Open "Developer Command Prompt for VS"
# with the WDK, or let the VS "Driver" project template pick this up.
# Output: build/<config>/aegis_kernel.sys  (test-signed by sign.cmd)
add_library(aegis_kernel MODULE
    kernel/aegis_common.h
    kernel/aegis_filter.c
    kernel/aegis_kernel.inf
)
set_target_properties(aegis_kernel PROPERTIES SUFFIX ".sys")
target_compile_definitions(aegis_kernel PRIVATE _KERNEL_MODE)
target_include_directories(aegis_kernel PRIVATE kernel)

# ── User-mode agent (C++) ────────────────────────────────────────────────────
# Plain Win32 exe, links fltLib + bcrypt. No code cert required to BUILD.
add_executable(aegis_agent
    kernel/aegis_common.h
    agent/aegis_agent.cpp
)
target_include_directories(aegis_agent PRIVATE kernel)

# ── Install/test-sign helper ────────────────────────────────────────────────
# sign.cmd generates a self-signed test cert and signs the .sys so it loads in
# Test Signing mode (bcdedit /set testsigning on). No EV/WHQL cert needed.
