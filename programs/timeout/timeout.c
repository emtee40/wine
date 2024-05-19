/*
 * timeout program
 *
 * Copyright (C) 2024 Myah Caron
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <math.h>

#include <windows.h>

#include "resources.h"

#include <wine/debug.h>

WINE_DEFAULT_DEBUG_CHANNEL(timeout);

static char* get_string(int which)
{
    char* msg;
    int len;
    WCHAR wmsg[2048];

    if (!LoadStringW(GetModuleHandleW(NULL), which, wmsg, ARRAY_SIZE(wmsg)))
    {
        WINE_ERR("LoadString failed for %d, error %ld\n", which, GetLastError());
        return NULL;
    }

    len = WideCharToMultiByte(GetOEMCP(), 0, wmsg, -1, NULL, 0, NULL, NULL);
    msg = malloc(len);
    if (!msg)
        return NULL;

    WideCharToMultiByte(GetOEMCP(), 0, wmsg, -1, msg, len, NULL, NULL);

    return msg;
}

#define RPRINTF(id) do\
    {\
        char* msg = get_string(id);\
        if (!msg)\
            break;\
        printf(msg);\
        free(msg);\
    } while (0)

#define RPRINTF_VA(id, ...) do\
    {\
        char* msg = get_string(id);\
        if (!msg)\
            break;\
        printf(msg, __VA_ARGS__);\
        free(msg);\
    } while (0)

static void usage(void)
{
    RPRINTF(STRING_USAGE);
}

static BOOL is_piped(void)
{
    DWORD count = 0;
    return !GetNumberOfConsoleInputEvents(GetStdHandle(STD_INPUT_HANDLE), &count);
}

static BOOL is_key_hit(void)
{
    INPUT_RECORD *records = NULL;
    DWORD count = 0, i;
    BOOL retval = FALSE;

    if (!GetNumberOfConsoleInputEvents(GetStdHandle(STD_INPUT_HANDLE), &count) || !count)
        return FALSE;

    records = malloc(count * sizeof(INPUT_RECORD));
    if (!records)
        return FALSE;

    if (!ReadConsoleInputA(GetStdHandle(STD_INPUT_HANDLE), records, count, &count))
        goto cleanup;

    for (i = 0; i < count; i++)
    {
        if (records[i].EventType == KEY_EVENT &&
            records[i].Event.KeyEvent.bKeyDown)
        {
          retval = TRUE;
          break;
        }
    }

cleanup:
    free(records);
    return retval;
}

static BOOL wait_for_keypress(DWORD timeout_millis)
{
    return WaitForSingleObject(GetStdHandle(STD_INPUT_HANDLE), timeout_millis) == WAIT_OBJECT_0 && is_key_hit();
}

static void sleep_without_timeout(BOOL nobreak)
{
    if (!nobreak)
    {
        RPRINTF(STRING_INFWAIT_PRESS_ANY_KEY);

        for (;;)
        {
            if (wait_for_keypress(INFINITE))
                break;
        }
    }
    else
    {
        RPRINTF(STRING_INFWAIT_PRESS_CTRL_C);

        for (;;)
        {
            Sleep(10000);
        }
    }
}

static int int_strlen(int number)
{
    if (number == 0)
        return 1;
    if (number < 0)
        return int_strlen(-number) + 1;

    return (int)log10((float) number) + 1;
}

static void pad_number(char* out, int number, int pad)
{
    int i, digits = int_strlen(number);

    for (i = 0; i < pad - digits; i++)
    {
        out[i] = ' ';
    }

    sprintf(out + i, "%d", number);
}

static void sleep_with_timeout(int timeout, BOOL nobreak)
{
    ULONGLONG start_ticks = GetTickCount64();
    ULONGLONG end_ticks = start_ticks + (timeout * 1000);
    LONGLONG ticks_remaining, wait_millis;
    int digits = int_strlen(timeout);
    char padded_timeout[10];

    pad_number(padded_timeout, timeout, digits);
    RPRINTF_VA(STRING_WAITING_FOR_SECONDS, padded_timeout);

    if (!nobreak)
        RPRINTF(STRING_WAIT_PRESS_KEY);
    else
        RPRINTF(STRING_WAIT_PRESS_CTRL_C);

    do
    {
        ticks_remaining = end_ticks - GetTickCount64();

        wait_millis = ticks_remaining;
        if (wait_millis > 1000)
            wait_millis = 1000;

        printf("\r");
        pad_number(padded_timeout, (int)((ticks_remaining + 500) / 1000), digits);
        RPRINTF_VA(STRING_WAITING_FOR_SECONDS, padded_timeout);

        if (wait_millis <= 0)
            break;

        if (!nobreak)
        {
            if (wait_for_keypress(wait_millis))
                break;
        }
        else
        {
            Sleep(wait_millis);
        }
    } while (ticks_remaining > 0);
}

static BOOL str_is_number(char* str)
{
    if (str[0] == '-')
        str++;

    while (*str)
    {
        if (!isdigit(*str++))
            return FALSE;
    }

    return TRUE;
}

static BOOL check_timeout_arg(char* str, BOOL timeout_set)
{
    if (timeout_set)
    {
        RPRINTF(STRING_TIMEOUT_ONLY_ONCE);
        return FALSE;
    }

    if (!str_is_number(str))
    {
        RPRINTF_VA(STRING_INVALID_TIMEOUT, str);
        return FALSE;
    }

    return TRUE;
}

int __cdecl main(int argc, char** argv)
{
    int i, timeout = 0;
    BOOL timeout_set = FALSE, nobreak = FALSE;

    if (argc == 1)
    {
        usage();
        return 1;
    }

    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == '-' || argv[i][0] == '/')
        {
            if (!strcmp(argv[i] + 1, "t"))
            {
                if (i == argc - 1)
                {
                    RPRINTF_VA(STRING_MISSING_VALUE_FOR_OPTION, argv[i]);
                    exit(1);
                }

                if (!check_timeout_arg(argv[++i], timeout_set))
                    return 1;

                timeout = atoi(argv[i]);
                timeout_set = TRUE;
            }
            else if (!strcmp(argv[i] + 1, "nobreak"))
            {
                nobreak = TRUE;
            }
            else if (!strcmp(argv[i] + 1, "?"))
            {
                usage();
                return 0;
            }
            else if (!strcmp(argv[i], "-1"))
            {
                timeout = -1;
                timeout_set = TRUE;
            }
            else
            {
                RPRINTF_VA(STRING_INVALID_ARGUMENT, argv[i]);
                usage();
                return 1;
            }
        }
        else
        {
            if (!check_timeout_arg(argv[i], timeout_set))
                return 1;

            timeout = atoi(argv[i]);
            timeout_set = TRUE;
        }
    }

    if (!timeout_set)
    {
        usage();
        return 1;
    }

    if (timeout < -1 || timeout > 99999)
    {
        RPRINTF(STRING_TIMEOUT_RANGE);
        return 1;
    }

    if (is_piped())
    {
        RPRINTF(STRING_NO_INPUT_REDIRECTION);
        return 1;
    }

    printf("\n");

    if (timeout < 0)
        sleep_without_timeout(nobreak);
    else
        sleep_with_timeout(timeout, nobreak);

    printf("\n");

    return 0;
}
