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
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <synchapi.h>
#include <stdbool.h>
#include <wchar.h>
#include <conio.h>
#include "timeout.h"

static int WINAPIV timeout_error_wprintf(int msg, ...)
{
    WCHAR msg_buffer[MAXSTRING];
    va_list va_args;
    int ret;

    LoadStringW(GetModuleHandleW(NULL), msg, msg_buffer, ARRAY_SIZE(msg_buffer));
    va_start(va_args, msg);
    ret = vfwprintf(stderr, msg_buffer, va_args);
    va_end(va_args);
    return ret;
}

static int WINAPIV timeout_message(int msg)
{
    WCHAR msg_buffer[MAXSTRING];

    LoadStringW(GetModuleHandleW(NULL), msg, msg_buffer, ARRAY_SIZE(msg_buffer));
    return fwprintf(stdout, msg_buffer);
}

static int WINAPIV timeout_wprintf(int msg, ...)
{
    WCHAR msg_buffer[MAXSTRING];
    va_list va_args;
    int ret;

    LoadStringW(GetModuleHandleW(NULL), msg, msg_buffer, ARRAY_SIZE(msg_buffer));
    va_start(va_args, msg);
    ret = vfwprintf(stdout, msg_buffer, va_args);
    va_end(va_args);
    return ret;
}

static volatile bool stop = false;

static BOOL WINAPI ctrl_c_handler(DWORD dwCtrlType)
{
    if (dwCtrlType == CTRL_C_EVENT)
    {
        stop = true;
        return TRUE;
    }
    return FALSE;
}

int __cdecl wmain(int argc, WCHAR *argv[])
{
    int wait_time = 0;
    int wait_time_valid = 0;
    int nobreak = 0;

    if (argc <= 1)
    {
        timeout_error_wprintf(STRING_BAD_COMMAND_LINE);
        return 1;
    }

    for (int i = 1; i < argc; i++)
    {
        if (wcscmp(argv[i], L"/?") == 0)
        {
            timeout_message(STRING_USAGE);
            return 0;
        }
        else if (wcsicmp(argv[i], L"/t") == 0)
        {
            if ((i + 1) < argc)
            {
                WCHAR *endptr = NULL;
                long l_wait_time;
                i++;
                l_wait_time = wcstol(argv[i], &endptr, 10);
                if (*endptr != L'\0') {
                    timeout_error_wprintf(STRING_BAD_COMMAND_LINE);
                    return 1;
                }
                if ((l_wait_time < -1) || (l_wait_time > 99999))
                {
                    timeout_error_wprintf(STRING_BAD_COMMAND_LINE);
                    return 1;
                }
                wait_time = (int)l_wait_time;
                wait_time_valid = 1;
            }
            else
            {
                timeout_error_wprintf(STRING_BAD_COMMAND_LINE);
                return 1;
            }
        }
        else if (wcsicmp(argv[i], L"/nobreak") == 0)
        {
            nobreak = 1;
        }
        else
        {
            timeout_error_wprintf(STRING_BAD_COMMAND_LINE);
            return 1;
        }
    }

    if (wait_time_valid == 0)
    {
        timeout_error_wprintf(STRING_BAD_COMMAND_LINE);
        return 1;
    }

    SetConsoleCtrlHandler(ctrl_c_handler, TRUE);

    if (nobreak)
    {
        SetConsoleCtrlHandler(ctrl_c_handler, TRUE);
    }

    for (int i = 0; (wait_time < 0) || (i < wait_time); i++)
    {
        timeout_wprintf(STRING_WAITING_SINCE, i);
        timeout_message((nobreak == 0) ? STRING_PRESS_KEY : STRING_PRESS_CRTLC);
        if (stop)
        {
            break;
        }
        if ((nobreak == 0) && _kbhit())
        {
            break;
        }
        Sleep(1000);
    }
    putc('\n', stdout);

    if (stop)
    {
        return STATUS_CONTROL_C_EXIT;
    }

    return 0;
}
