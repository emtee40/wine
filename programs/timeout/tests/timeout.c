/*
 * Copyright 2024 Michele Dionisio <michele.dionisio@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <windows.h>
#include "wine/test.h"

#define run_timeout_stdin(a, b) _run_timeout_stdin(__FILE__, __LINE__, a, b)
static void _run_timeout_stdin(const char *file, int line, const char *commandline, int exitcode_expected)
{
    PROCESS_INFORMATION process_info = {0};
    STARTUPINFOA startup_info;
    char cmd[4096];
    DWORD exitcode;

    memset(&startup_info, 0, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup_info.hStdOutput = NULL;
    startup_info.hStdError = NULL;

    sprintf(cmd, "timeout.exe %s", commandline);

    trace("Running %s\n", cmd);

    CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &startup_info, &process_info);

    WaitForSingleObject(process_info.hProcess, INFINITE);
    GetExitCodeProcess(process_info.hProcess, &exitcode);
    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);
    ok_(file, line)(exitcode == exitcode_expected, "Expected exitcode %d, got %ld\n",
                    exitcode_expected, exitcode);
}

static void test_basic(void)
{
    /* No options */
    run_timeout_stdin("", 1);

    /* /? */
    run_timeout_stdin("/?", 0);

    /* /T 1 /NOBREAK */
    run_timeout_stdin("/T 1 /NOBREAK", 0);

    /* 1 /NOBREAK */
    run_timeout_stdin("/T 1 /NOBREAK", 0);

    /* /T 1ab /NOBREAK */
    run_timeout_stdin("/T 1ab /NOBREAK", 1);

    /* /T -3 /NOBREAK */
    run_timeout_stdin("/T -3 /NOBREAK", 1);

    /* /T 10000000 /NOBREAK */
    run_timeout_stdin("/T 10000000 /NOBREAK", 1);
}

#define run_timeout_ctrlc(a, b) _run_timeout_ctrlc(__FILE__, __LINE__, a, b)
static void _run_timeout_ctrlc(const char *file, int line, const char *option, DWORD exitcode_expected)
{
    PROCESS_INFORMATION process_info = {0};
    STARTUPINFOA startup_info;
    char cmd[4096];
    DWORD status, exitcode;
    DWORD64 tick_count;
    BOOL ret;

    memset(&startup_info, 0, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup_info.hStdOutput = NULL;
    startup_info.hStdError = NULL;

    SetConsoleCtrlHandler(NULL, FALSE);
    sprintf(cmd, "timeout.exe /T 8 %s", option);
    ret = CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &startup_info, &process_info);
    ok(ret, "CreateProcessA failed: %lu\n", GetLastError());

    /* wait for process to be started */
    status = WaitForSingleObject(process_info.hProcess, 2000);
    ok_(file, line)(status == WAIT_TIMEOUT, "WaitForSingleObject returned %#lx (expecting WAIT_TIMEOUT)\n", status);

    tick_count = GetTickCount64();

    SetConsoleCtrlHandler(NULL, TRUE);
    ret = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
    ok_(file, line)(ret, "GenerateConsoleCtrlEvent failed: %lu\n", GetLastError());

    status = WaitForSingleObject(process_info.hProcess, INFINITE);
    ok_(file, line)(status == WAIT_OBJECT_0, "WaitForSingleObject returned %#lx (expecting WAIT_OBJECT_0)\n", status);

    tick_count = GetTickCount64() - tick_count;
    ok_(file, line)(tick_count < 2000, "Process has not been stopped by ctrl-c\n");

    ret = GetExitCodeProcess(process_info.hProcess, &exitcode);
    ok_(file, line)(ret, "GetExitCodeProcess failed\n");

    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);
    ok_(file, line)(exitcode == exitcode_expected, "Expected exitcode %ld, got %lx\n",
                    exitcode_expected, exitcode);
}

static void test_ctrlc(void)
{
    /* don't temper with winetest (and its parent) */
    FreeConsole();
    AllocConsole();

    run_timeout_ctrlc("", STATUS_CONTROL_C_EXIT);
    run_timeout_ctrlc("/nobreak", 1);
}

START_TEST(timeout)
{
    test_basic();
    /* must be last in list (changes current console) */
    test_ctrlc();
}
