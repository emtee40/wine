/*
 * XDND handler code
 *
 * Copyright 2003 Ulrich Czekalla
 * Copyright 2007 Damjan Jovanovic
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

#define COBJMACROS
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "x11drv_dll.h"
#include "shellapi.h"
#include "shlobj.h"

#include "wine/debug.h"
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(xdnd);

static IDataObject *xdnd_data_object;

static CRITICAL_SECTION xdnd_cs;
static CRITICAL_SECTION_DEBUG critsect_debug =
{
    0, 0, &xdnd_cs,
    { &critsect_debug.ProcessLocksList, &critsect_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": xdnd_cs") }
};
static CRITICAL_SECTION xdnd_cs = { &critsect_debug, -1, 0, 0, 0, 0 };


static struct format_entry *next_format( struct format_entry *entry )
{
    return (struct format_entry *)&entry->data[(entry->size + 7) & ~7];
}

static const char *debugstr_format( int format )
{
    WCHAR buffer[256];
    switch (format)
    {
#define X(x) case x: return #x;
    X(CF_TEXT)
    X(CF_BITMAP)
    X(CF_METAFILEPICT)
    X(CF_SYLK)
    X(CF_DIF)
    X(CF_TIFF)
    X(CF_OEMTEXT)
    X(CF_DIB)
    X(CF_PALETTE)
    X(CF_PENDATA)
    X(CF_RIFF)
    X(CF_WAVE)
    X(CF_UNICODETEXT)
    X(CF_ENHMETAFILE)
    X(CF_HDROP)
    X(CF_LOCALE)
    X(CF_DIBV5)
#undef X
    }

    if (CF_PRIVATEFIRST <= format && format <= CF_PRIVATELAST) return "some private object";
    if (CF_GDIOBJFIRST <= format && format <= CF_GDIOBJLAST) return "some GDI object";
    GetClipboardFormatNameW( format, buffer, sizeof(buffer) );
    return debugstr_w( buffer );
}

struct data_object
{
    IDataObject IDataObject_iface;
    LONG refcount;

    HWND target_hwnd; /* the last window the mouse was over */
    POINT target_pos;
    DWORD target_effect;
    IDropTarget *drop_target;

    struct format_entry *entries_end;
    struct format_entry entries[];
};

static struct data_object *data_object_from_IDataObject( IDataObject *iface )
{
    return CONTAINING_RECORD( iface, struct data_object, IDataObject_iface );
}

struct format_iterator
{
    IEnumFORMATETC IEnumFORMATETC_iface;
    LONG refcount;

    struct format_entry *entry;
    IDataObject *object;
};

static inline struct format_iterator *format_iterator_from_IEnumFORMATETC( IEnumFORMATETC *iface )
{
    return CONTAINING_RECORD(iface, struct format_iterator, IEnumFORMATETC_iface);
}

static HRESULT WINAPI format_iterator_QueryInterface( IEnumFORMATETC *iface, REFIID iid, void **obj )
{
    struct format_iterator *iterator = format_iterator_from_IEnumFORMATETC( iface );

    TRACE( "iterator %p, iid %s, obj %p\n", iterator, debugstr_guid(iid), obj );

    if (IsEqualIID( iid, &IID_IUnknown ) || IsEqualIID( iid, &IID_IEnumFORMATETC ))
    {
        IEnumFORMATETC_AddRef( &iterator->IEnumFORMATETC_iface );
        *obj = &iterator->IEnumFORMATETC_iface;
        return S_OK;
    }

    *obj = NULL;
    WARN( "%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid) );
    return E_NOINTERFACE;
}

static ULONG WINAPI format_iterator_AddRef( IEnumFORMATETC *iface )
{
    struct format_iterator *iterator = format_iterator_from_IEnumFORMATETC( iface );
    ULONG ref = InterlockedIncrement( &iterator->refcount );
    TRACE( "iterator %p increasing refcount to %lu.\n", iterator, ref );
    return ref;
}

static ULONG WINAPI format_iterator_Release(IEnumFORMATETC *iface)
{
    struct format_iterator *iterator = format_iterator_from_IEnumFORMATETC( iface );
    ULONG ref = InterlockedDecrement( &iterator->refcount );

    TRACE( "iterator %p increasing refcount to %lu.\n", iterator, ref );

    if (!ref)
    {
        IDataObject_Release( iterator->object );
        free( iterator );
    }

    return ref;
}

static HRESULT WINAPI format_iterator_Next( IEnumFORMATETC *iface, ULONG count, FORMATETC *formats, ULONG *ret )
{
    struct format_iterator *iterator = format_iterator_from_IEnumFORMATETC( iface );
    struct data_object *object = data_object_from_IDataObject( iterator->object );
    struct format_entry *entry;
    UINT i;

    TRACE( "iterator %p, count %lu, formats %p, ret %p\n", iterator, count, formats, ret );

    for (entry = iterator->entry, i = 0; entry < object->entries_end && i < count; entry = next_format( entry ), i++)
    {
        formats[i].cfFormat = entry->format;
        formats[i].ptd = NULL;
        formats[i].dwAspect = DVASPECT_CONTENT;
        formats[i].lindex = -1;
        formats[i].tymed = TYMED_HGLOBAL;
    }

    iterator->entry = entry;
    if (ret) *ret = i;
    return (i == count) ? S_OK : S_FALSE;
}

static HRESULT WINAPI format_iterator_Skip( IEnumFORMATETC *iface, ULONG count )
{
    struct format_iterator *iterator = format_iterator_from_IEnumFORMATETC( iface );
    struct data_object *object = data_object_from_IDataObject( iterator->object );
    struct format_entry *entry;

    TRACE( "iterator %p, count %lu\n", iterator, count );

    for (entry = iterator->entry; entry < object->entries_end; entry = next_format( entry ))
        if (!count--) break;

    iterator->entry = entry;
    return count ? S_FALSE : S_OK;
}

static HRESULT WINAPI format_iterator_Reset( IEnumFORMATETC *iface )
{
    struct format_iterator *iterator = format_iterator_from_IEnumFORMATETC( iface );
    struct data_object *object = data_object_from_IDataObject( iterator->object );

    TRACE( "iterator %p\n", iterator );
    iterator->entry = object->entries;
    return S_OK;
}

static HRESULT format_iterator_create( IDataObject *object, IEnumFORMATETC **out );

static HRESULT WINAPI format_iterator_Clone( IEnumFORMATETC *iface, IEnumFORMATETC **out )
{
    struct format_iterator *iterator = format_iterator_from_IEnumFORMATETC( iface );
    TRACE( "iterator %p, out %p\n", iterator, out );
    return format_iterator_create( iterator->object, out );
}

static const IEnumFORMATETCVtbl format_iterator_vtbl =
{
    format_iterator_QueryInterface,
    format_iterator_AddRef,
    format_iterator_Release,
    format_iterator_Next,
    format_iterator_Skip,
    format_iterator_Reset,
    format_iterator_Clone,
};

static HRESULT format_iterator_create( IDataObject *object, IEnumFORMATETC **out )
{
    struct format_iterator *iterator;

    if (!(iterator = calloc( 1, sizeof(*iterator) ))) return E_OUTOFMEMORY;
    iterator->IEnumFORMATETC_iface.lpVtbl = &format_iterator_vtbl;
    iterator->refcount = 1;
    IDataObject_AddRef( (iterator->object = object) );
    iterator->entry = data_object_from_IDataObject(object)->entries;

    *out = &iterator->IEnumFORMATETC_iface;
    TRACE( "created object %p iterator %p\n", object, iterator );
    return S_OK;
}

static HRESULT WINAPI data_object_QueryInterface( IDataObject *iface, REFIID iid, void **obj )
{
    struct data_object *object = data_object_from_IDataObject( iface );

    TRACE( "object %p, iid %s, obj %p\n", object, debugstr_guid(iid), obj );

    if (IsEqualIID( iid, &IID_IUnknown ) || IsEqualIID( iid, &IID_IDataObject ))
    {
        IDataObject_AddRef( &object->IDataObject_iface );
        *obj = &object->IDataObject_iface;
        return S_OK;
    }

    *obj = NULL;
    WARN( "%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid) );
    return E_NOINTERFACE;
}

static ULONG WINAPI data_object_AddRef( IDataObject *iface )
{
    struct data_object *object = data_object_from_IDataObject( iface );
    ULONG ref = InterlockedIncrement( &object->refcount );
    TRACE( "object %p increasing refcount to %lu.\n", object, ref );
    return ref;
}

static ULONG WINAPI data_object_Release( IDataObject *iface )
{
    struct data_object *object = data_object_from_IDataObject( iface );
    ULONG ref = InterlockedDecrement( &object->refcount );

    TRACE( "object %p decreasing refcount to %lu.\n", object, ref );

    if (!ref)
    {
        if (object->drop_target)
        {
            HRESULT hr = IDropTarget_DragLeave( object->drop_target );
            if (FAILED(hr)) WARN( "IDropTarget_DragLeave returned %#lx\n", hr );
            IDropTarget_Release( object->drop_target );
        }

        free( object );
    }

    return ref;
}

static HRESULT WINAPI data_object_GetData( IDataObject *iface, FORMATETC *format, STGMEDIUM *medium )
{
    struct data_object *object = data_object_from_IDataObject( iface );
    struct format_entry *iter;
    HRESULT hr;

    TRACE( "object %p, format %p (%s), medium %p\n", object, format, debugstr_format(format->cfFormat), medium );

    if (FAILED(hr = IDataObject_QueryGetData( iface, format ))) return hr;

    for (iter = object->entries; iter < object->entries_end; iter = next_format( iter ))
    {
        if (iter->format == format->cfFormat)
        {
            medium->tymed = TYMED_HGLOBAL;
            medium->hGlobal = GlobalAlloc( GMEM_FIXED | GMEM_ZEROINIT, iter->size );
            if (medium->hGlobal == NULL) return E_OUTOFMEMORY;
            memcpy( GlobalLock( medium->hGlobal ), iter->data, iter->size );
            GlobalUnlock( medium->hGlobal );
            medium->pUnkForRelease = 0;
            return S_OK;
        }
    }

    return DATA_E_FORMATETC;
}

static HRESULT WINAPI data_object_GetDataHere( IDataObject *iface, FORMATETC *format, STGMEDIUM *medium )
{
    struct data_object *object = data_object_from_IDataObject( iface );
    FIXME( "object %p, format %p, medium %p stub!\n", object, format, medium );
    return DATA_E_FORMATETC;
}

static HRESULT WINAPI data_object_QueryGetData( IDataObject *iface, FORMATETC *format )
{
    struct data_object *object = data_object_from_IDataObject( iface );
    struct format_entry *iter;

    TRACE( "object %p, format %p (%s)\n", object, format, debugstr_format(format->cfFormat) );

    if (format->tymed && !(format->tymed & TYMED_HGLOBAL))
    {
        FIXME("only HGLOBAL medium types supported right now\n");
        return DV_E_TYMED;
    }
    /* Windows Explorer ignores .dwAspect and .lindex for CF_HDROP,
     * and we have no way to implement them on XDnD anyway, so ignore them too.
     */

    for (iter = object->entries; iter < object->entries_end; iter = next_format( iter ))
    {
        if (iter->format == format->cfFormat)
        {
            TRACE("application found %s\n", debugstr_format(format->cfFormat));
            return S_OK;
        }
    }
    TRACE("application didn't find %s\n", debugstr_format(format->cfFormat));
    return DV_E_FORMATETC;
}

static HRESULT WINAPI data_object_GetCanonicalFormatEtc( IDataObject *iface, FORMATETC *format, FORMATETC *out )
{
    struct data_object *object = data_object_from_IDataObject( iface );
    FIXME( "object %p, format %p, out %p stub!\n", object, format, out );
    out->ptd = NULL;
    return E_NOTIMPL;
}

static HRESULT WINAPI data_object_SetData( IDataObject *iface, FORMATETC *format, STGMEDIUM *medium, BOOL release )
{
    struct data_object *object = data_object_from_IDataObject( iface );
    FIXME( "object %p, format %p, medium %p, release %u stub!\n", object, format, medium, release );
    return E_NOTIMPL;
}

static HRESULT WINAPI data_object_EnumFormatEtc( IDataObject *iface, DWORD direction, IEnumFORMATETC **out )
{
    struct data_object *object = data_object_from_IDataObject( iface );

    TRACE( "object %p, direction %lu, out %p\n", object, direction, out );

    if (direction != DATADIR_GET)
    {
        FIXME("only the get direction is implemented\n");
        return E_NOTIMPL;
    }

    return format_iterator_create( iface, out );
}

static HRESULT WINAPI data_object_DAdvise( IDataObject *iface, FORMATETC *format, DWORD flags,
                                           IAdviseSink *sink, DWORD *connection )
{
    struct data_object *object = data_object_from_IDataObject( iface );
    FIXME( "object %p, format %p, flags %#lx, sink %p, connection %p stub!\n",
           object, format, flags, sink, connection );
    return OLE_E_ADVISENOTSUPPORTED;
}

static HRESULT WINAPI data_object_DUnadvise( IDataObject *iface, DWORD connection )
{
    struct data_object *object = data_object_from_IDataObject( iface );
    FIXME( "object %p, connection %lu stub!\n", object, connection );
    return OLE_E_ADVISENOTSUPPORTED;
}

static HRESULT WINAPI data_object_EnumDAdvise( IDataObject *iface, IEnumSTATDATA **advise )
{
    struct data_object *object = data_object_from_IDataObject( iface );
    FIXME( "object %p, advise %p stub!\n", object, advise );
    return OLE_E_ADVISENOTSUPPORTED;
}

static IDataObjectVtbl data_object_vtbl =
{
    data_object_QueryInterface,
    data_object_AddRef,
    data_object_Release,
    data_object_GetData,
    data_object_GetDataHere,
    data_object_QueryGetData,
    data_object_GetCanonicalFormatEtc,
    data_object_SetData,
    data_object_EnumFormatEtc,
    data_object_DAdvise,
    data_object_DUnadvise,
    data_object_EnumDAdvise,
};

static HRESULT data_object_create( UINT entries_size, const struct format_entry *entries, IDataObject **out )
{
    struct data_object *object;

    if (!(object = calloc( 1, sizeof(*object) + entries_size ))) return E_OUTOFMEMORY;
    object->IDataObject_iface.lpVtbl = &data_object_vtbl;
    object->refcount = 1;

    object->entries_end = (struct format_entry *)((char *)object->entries + entries_size);
    memcpy( object->entries, entries, entries_size );
    *out = &object->IDataObject_iface;

    return S_OK;
}

static struct data_object *get_data_object( BOOL clear )
{
    IDataObject *iface;

    EnterCriticalSection( &xdnd_cs );
    if ((iface = xdnd_data_object))
    {
        if (clear) xdnd_data_object = NULL;
        else IDataObject_AddRef( iface );
    }
    LeaveCriticalSection( &xdnd_cs );

    if (!iface) return NULL;
    return data_object_from_IDataObject( iface );
}

/* Based on functions in dlls/ole32/ole2.c */
static HANDLE get_droptarget_local_handle(HWND hwnd)
{
    static const WCHAR prop_marshalleddroptarget[] =
        {'W','i','n','e','M','a','r','s','h','a','l','l','e','d','D','r','o','p','T','a','r','g','e','t',0};
    HANDLE handle;
    HANDLE local_handle = 0;

    handle = GetPropW(hwnd, prop_marshalleddroptarget);
    if (handle)
    {
        DWORD pid;
        HANDLE process;

        GetWindowThreadProcessId(hwnd, &pid);
        process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        if (process)
        {
            DuplicateHandle(process, handle, GetCurrentProcess(), &local_handle, 0, FALSE, DUPLICATE_SAME_ACCESS);
            CloseHandle(process);
        }
    }
    return local_handle;
}

static HRESULT create_stream_from_map(HANDLE map, IStream **stream)
{
    HRESULT hr = E_OUTOFMEMORY;
    HGLOBAL hmem;
    void *data;
    MEMORY_BASIC_INFORMATION info;

    data = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if(!data) return hr;

    VirtualQuery(data, &info, sizeof(info));
    TRACE("size %d\n", (int)info.RegionSize);

    hmem = GlobalAlloc(GMEM_MOVEABLE, info.RegionSize);
    if(hmem)
    {
        memcpy(GlobalLock(hmem), data, info.RegionSize);
        GlobalUnlock(hmem);
        hr = CreateStreamOnHGlobal(hmem, TRUE, stream);
    }
    UnmapViewOfFile(data);
    return hr;
}

static IDropTarget* get_droptarget_pointer(HWND hwnd)
{
    IDropTarget *droptarget = NULL;
    HANDLE map;
    IStream *stream;

    map = get_droptarget_local_handle(hwnd);
    if(!map) return NULL;

    if(SUCCEEDED(create_stream_from_map(map, &stream)))
    {
        CoUnmarshalInterface(stream, &IID_IDropTarget, (void**)&droptarget);
        IStream_Release(stream);
    }
    CloseHandle(map);
    return droptarget;
}


/* Recursively searches for a window on given coordinates in a drag&drop specific manner.
 *
 * Don't use WindowFromPoint instead, because it omits the STATIC and transparent
 * windows, but they can be a valid drop targets if have WS_EX_ACCEPTFILES set.
 */
static HWND window_from_point_dnd(HWND hwnd, POINT point)
{
    HWND child;
    ScreenToClient(hwnd, &point);
    while ((child = ChildWindowFromPointEx(hwnd, point, CWP_SKIPDISABLED | CWP_SKIPINVISIBLE)) && child != hwnd)
    {
       MapWindowPoints(hwnd, child, &point, 1);
       hwnd = child;
    }

    return hwnd;
}

/* Returns the first window down the hierarchy that has WS_EX_ACCEPTFILES set or
 * returns NULL, if such window does not exists.
 */
static HWND window_accepting_files(HWND hwnd)
{
    while (hwnd && !(GetWindowLongW(hwnd, GWL_EXSTYLE) & WS_EX_ACCEPTFILES))
        /* MUST to be GetParent, not GetAncestor, because the owner window
         * (with WS_EX_ACCEPTFILES) of a window with WS_POPUP is a valid
         * drop target. GetParent works exactly this way!
         */
        hwnd = GetParent(hwnd);
    return hwnd;
}

/**************************************************************************
 *           x11drv_dnd_position_event
 *
 * Handle an XdndPosition event.
 */
NTSTATUS WINAPI x11drv_dnd_position_event( void *arg, ULONG size )
{
    struct dnd_position_event_params *params = arg;
    int accept = 0; /* Assume we're not accepting */
    DWORD effect = params->effect;
    POINTL pointl = { .x = params->point.x, .y = params->point.y };
    struct data_object *object;
    HWND targetWindow;
    HRESULT hr;

    if (!(object = get_data_object( FALSE ))) return STATUS_INVALID_PARAMETER;

    object->target_pos = params->point;
    targetWindow = window_from_point_dnd( UlongToHandle( params->hwnd ), object->target_pos );

    if (!object->drop_target || object->target_hwnd != targetWindow)
    {
        /* Notify OLE of DragEnter. Result determines if we accept */
        HWND dropTargetWindow;

        if (object->drop_target)
        {
            hr = IDropTarget_DragLeave( object->drop_target );
            if (FAILED(hr)) WARN( "IDropTarget_DragLeave returned %#lx\n", hr );
            IDropTarget_Release( object->drop_target );
            object->drop_target = NULL;
        }

        dropTargetWindow = targetWindow;
        do { object->drop_target = get_droptarget_pointer( dropTargetWindow ); }
        while (!object->drop_target && !!(dropTargetWindow = GetParent( dropTargetWindow )));
        object->target_hwnd = targetWindow;

        if (object->drop_target)
        {
            DWORD effect_ignore = effect;
            hr = IDropTarget_DragEnter( object->drop_target, &object->IDataObject_iface,
                                        MK_LBUTTON, pointl, &effect_ignore );
            if (hr == S_OK) TRACE( "the application accepted the drop (effect = %ld)\n", effect_ignore );
            else
            {
                WARN( "IDropTarget_DragEnter returned %#lx\n", hr );
                IDropTarget_Release( object->drop_target );
                object->drop_target = NULL;
            }
        }
    }
    else if (object->drop_target)
    {
        hr = IDropTarget_DragOver( object->drop_target, MK_LBUTTON, pointl, &effect );
        if (hr == S_OK) object->target_effect = effect;
        else WARN( "IDropTarget_DragOver returned %#lx\n", hr );
    }

    if (object->drop_target && object->target_effect != DROPEFFECT_NONE)
        accept = 1;
    else
    {
        /* fallback search for window able to accept these files. */
        FORMATETC format = {.cfFormat = CF_HDROP};

        if (window_accepting_files(targetWindow) && SUCCEEDED(IDataObject_QueryGetData( &object->IDataObject_iface, &format )))
        {
            accept = 1;
            effect = DROPEFFECT_COPY;
        }
    }

    if (!accept) effect = DROPEFFECT_NONE;
    IDataObject_Release( &object->IDataObject_iface );

    return NtCallbackReturn( &effect, sizeof(effect), STATUS_SUCCESS );
}

NTSTATUS WINAPI x11drv_dnd_drop_event( void *args, ULONG size )
{
    struct dnd_drop_event_params *params = args;
    HWND hwnd = UlongToHandle( params->hwnd );
    DWORD effect;
    int accept = 0; /* Assume we're not accepting */
    struct data_object *object;
    BOOL drop_file = TRUE;

    if (!(object = get_data_object( TRUE ))) return STATUS_INVALID_PARAMETER;
    effect = object->target_effect;

    /* Notify OLE of Drop */
    if (object->drop_target && effect != DROPEFFECT_NONE)
    {
        POINTL pointl = {object->target_pos.x, object->target_pos.y};
        HRESULT hr;

        hr = IDropTarget_Drop( object->drop_target, &object->IDataObject_iface,
                               MK_LBUTTON, pointl, &effect );
        if (hr == S_OK)
        {
            if (effect != DROPEFFECT_NONE)
            {
                TRACE("drop succeeded\n");
                accept = 1;
                drop_file = FALSE;
            }
            else
                TRACE("the application refused the drop\n");
        }
        else if (FAILED(hr))
            WARN("drop failed, error 0x%08lx\n", hr);
        else
        {
            WARN("drop returned 0x%08lx\n", hr);
            drop_file = FALSE;
        }
    }
    else if (object->drop_target)
    {
        HRESULT hr = IDropTarget_DragLeave( object->drop_target );
        if (FAILED(hr)) WARN( "IDropTarget_DragLeave returned %#lx\n", hr );
        IDropTarget_Release( object->drop_target );
        object->drop_target = NULL;
    }

    if (drop_file)
    {
        /* Only send WM_DROPFILES if Drop didn't succeed or DROPEFFECT_NONE was set.
         * Doing both causes winamp to duplicate the dropped files (#29081) */
        HWND hwnd_drop = window_accepting_files(window_from_point_dnd( hwnd, object->target_pos ));
        FORMATETC format = {.cfFormat = CF_HDROP};
        STGMEDIUM medium;

        if (hwnd_drop && SUCCEEDED(IDataObject_GetData( &object->IDataObject_iface, &format, &medium )))
        {
            DROPFILES *drop = GlobalLock( medium.hGlobal );
            void *files = (char *)drop + drop->pFiles;
            RECT rect;

            drop->pt = object->target_pos;
            drop->fNC = !ScreenToClient( hwnd, &drop->pt ) || !GetClientRect( hwnd, &rect ) || !PtInRect( &rect, drop->pt );
            TRACE( "Sending WM_DROPFILES: hwnd %p, pt %s, fNC %u, files %p (%s)\n", hwnd,
                   wine_dbgstr_point( &drop->pt), drop->fNC, files, debugstr_w(files) );
            GlobalUnlock( medium.hGlobal );

            PostMessageW( hwnd, WM_DROPFILES, (WPARAM)medium.hGlobal, 0 );
            accept = 1;
            effect = DROPEFFECT_COPY;
        }
    }

    TRACE("effectRequested(0x%lx) accept(%d) performed(0x%lx) at x(%ld),y(%ld)\n",
          object->target_effect, accept, effect, object->target_pos.x, object->target_pos.y);

    if (!accept) effect = DROPEFFECT_NONE;
    IDataObject_Release( &object->IDataObject_iface );

    return NtCallbackReturn( &effect, sizeof(effect), STATUS_SUCCESS );
}

/**************************************************************************
 *           x11drv_dnd_leave_event
 *
 * Handle an XdndLeave event.
 */
NTSTATUS WINAPI x11drv_dnd_leave_event( void *params, ULONG size )
{
    struct data_object *object;

    TRACE("DND Operation canceled\n");

    if ((object = get_data_object( TRUE ))) IDataObject_Release( &object->IDataObject_iface );
    return STATUS_SUCCESS;
}


/**************************************************************************
 *           x11drv_dnd_enter_event
 */
NTSTATUS WINAPI x11drv_dnd_enter_event( void *args, ULONG size )
{
    UINT formats_size = size - offsetof(struct dnd_enter_event_params, entries);
    struct dnd_enter_event_params *params = args;
    IDataObject *object, *previous;

    if (FAILED(data_object_create( formats_size, params->entries, &object ))) return STATUS_NO_MEMORY;

    EnterCriticalSection( &xdnd_cs );
    previous = xdnd_data_object;
    xdnd_data_object = object;
    LeaveCriticalSection( &xdnd_cs );

    if (previous) IDataObject_Release( previous );
    return STATUS_SUCCESS;
}


NTSTATUS WINAPI x11drv_dnd_post_drop( void *args, ULONG size )
{
    UINT drop_size = size - offsetof(struct dnd_post_drop_params, drop);
    struct dnd_post_drop_params *params = args;
    HDROP handle;

    if ((handle = GlobalAlloc( GMEM_SHARE, drop_size )))
    {
        DROPFILES *ptr = GlobalLock( handle );
        HWND hwnd;
        memcpy( ptr, &params->drop, drop_size );
        hwnd = UlongToHandle( ptr->fWide );
        ptr->fWide = TRUE;
        GlobalUnlock( handle );
        PostMessageW( hwnd, WM_DROPFILES, (WPARAM)handle, 0 );
    }

    return STATUS_SUCCESS;
}
