/*
 * Copyright 2024 Rémi Bernon for CodeWeavers
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

#include "desk_private.h"

#include <commctrl.h>
#include <cpl.h>
#include "ole2.h"

#include "wine/debug.h"
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(deskcpl);

static HMODULE module;

struct device_entry
{
    struct list entry;
    DISPLAY_DEVICEW adapter;
};
static struct list devices = LIST_INIT( devices );

static void clear_devices( HWND hwnd )
{
    struct device_entry *entry, *next;

    LIST_FOR_EACH_ENTRY_SAFE( entry, next, &devices, struct device_entry, entry )
    {
        list_remove( &entry->entry );
        free( entry );
    }
}

static void refresh_device_list( HWND hwnd )
{
    DISPLAY_DEVICEW adapter = {.cb = sizeof(adapter)};
    struct device_entry *entry;
    UINT i;

    clear_devices( hwnd );

    for (i = 0; EnumDisplayDevicesW( NULL, i, &adapter, 0 ); ++i)
    {
        /* FIXME: Implement detached adapters */
        if (!(adapter.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP)) continue;
        if (!(entry = calloc( 1, sizeof(*entry) ))) return;
        entry->adapter = adapter;
        list_add_tail( &devices, &entry->entry );
    }
}

static INT_PTR CALLBACK desktop_dialog_proc( HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam )
{
    TRACE( "hwnd %p, msg %#x, wparam %#Ix, lparam %#Ix\n", hwnd, msg, wparam, lparam );

    switch (msg)
    {
    case WM_INITDIALOG:
        refresh_device_list( hwnd );
        return TRUE;

    case WM_COMMAND:
        return TRUE;

    case WM_NOTIFY:
        return TRUE;
    }

    return FALSE;
}

static int CALLBACK property_sheet_callback( HWND hwnd, UINT msg, LPARAM lparam )
{
    TRACE( "hwnd %p, msg %#x, lparam %#Ix\n", hwnd, msg, lparam );
    return 0;
}

static void create_property_sheets( HWND parent )
{
    INITCOMMONCONTROLSEX init =
    {
        .dwSize = sizeof(INITCOMMONCONTROLSEX),
        .dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES,
    };
    PROPSHEETPAGEW pages[] =
    {
        {
            .dwSize = sizeof(PROPSHEETPAGEW),
            .hInstance = module,
            .pszTemplate = MAKEINTRESOURCEW( IDD_DESKTOP ),
            .pfnDlgProc = desktop_dialog_proc,
        },
    };
    PROPSHEETHEADERW header =
    {
        .dwSize = sizeof(PROPSHEETHEADERW),
        .dwFlags = PSH_PROPSHEETPAGE | PSH_USEICONID | PSH_USECALLBACK,
        .hwndParent = parent,
        .hInstance = module,
        .pszCaption = MAKEINTRESOURCEW( IDS_CPL_NAME ),
        .nPages = ARRAY_SIZE(pages),
        .ppsp = pages,
        .pfnCallback = property_sheet_callback,
    };
    ACTCTXW context_desc =
    {
        .cbSize = sizeof(ACTCTXW),
        .hModule = module,
        .lpResourceName = MAKEINTRESOURCEW( 124 ),
        .dwFlags = ACTCTX_FLAG_HMODULE_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID,
    };
    ULONG_PTR cookie;
    HANDLE context;
    BOOL activated;

    OleInitialize( NULL );

    context = CreateActCtxW( &context_desc );
    if (context == INVALID_HANDLE_VALUE) activated = FALSE;
    else activated = ActivateActCtx( context, &cookie );

    InitCommonControlsEx( &init );
    PropertySheetW( &header );

    if (activated) DeactivateActCtx( 0, cookie );
    ReleaseActCtx( context );
    OleUninitialize();
}

/*********************************************************************
 * CPlApplet (desk.cpl.@)
 */
LONG CALLBACK CPlApplet( HWND hwnd, UINT command, LPARAM param1, LPARAM param2 )
{
    TRACE( "hwnd %p, command %u, param1 %#Ix, param2 %#Ix\n", hwnd, command, param1, param2 );

    switch (command)
    {
    case CPL_INIT:
        return TRUE;

    case CPL_GETCOUNT:
        return 1;

    case CPL_INQUIRE:
    {
        CPLINFO *info = (CPLINFO *)param2;
        info->idIcon = ICO_MAIN;
        info->idName = IDS_CPL_NAME;
        info->idInfo = IDS_CPL_INFO;
        info->lData = 0;
        return TRUE;
    }

    case CPL_DBLCLK:
        create_property_sheets( hwnd );
        break;

    case CPL_STOP:
        break;
    }

    return FALSE;
}

/*********************************************************************
 *  DllMain
 */
BOOL WINAPI DllMain( HINSTANCE instance, DWORD reason, LPVOID reserved )
{
    TRACE( "instance %p, reason %ld, reserved %p\n", instance, reason, reserved );

    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls( instance );
        module = instance;
    }

    return TRUE;
}
