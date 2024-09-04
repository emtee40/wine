/* Unit test suite for *Information* Registry API functions
 *
 * Copyright 2024 Grigory Vasilyev
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
 *
 */

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "wine/test.h"
#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "winuser.h"
#include "winternl.h"

static void test_get_firmware_type(void)
{
    FIRMWARE_TYPE ft;
    BOOL status;

    status = GetFirmwareType(&ft);
    if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
    {
        skip("GetFirmwareType not implemented.\n");
        return;
    }

    ok(status == TRUE, "Expected TRUE.\n");

    ok(ft == FirmwareTypeBios || ft == FirmwareTypeUefi,
       "Expected FirmwareTypeBios or FirmwareTypeUefi, got %08x\n", ft);

    status = GetFirmwareType(NULL);
    ok(status == FALSE && GetLastError() == ERROR_INVALID_PARAMETER,
       "Expected FALSE and GetLastError() == ERROR_INVALID_PARAMETER\n");
}

START_TEST(firmware)
{
    test_get_firmware_type();
}
