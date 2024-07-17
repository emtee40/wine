/*
 * EnumerableObjectCollection
 *
 * Copyright 2024 Kevin Martinez
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

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define COBJMACROS

#include "wine/debug.h"
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "shlwapi.h"

#include "shell32_main.h"

WINE_DEFAULT_DEBUG_CHANNEL(shell);

struct enum_objects
{
    IEnumObjects IEnumObjects_iface;
    LONG ref;
};

static inline struct enum_objects *impl_from_IEnumObjects(IEnumObjects *iface)
{
    return CONTAINING_RECORD(iface, struct enum_objects, IEnumObjects_iface);
}

static HRESULT WINAPI enum_objects_QueryInterface(IEnumObjects *iface, REFIID riid, void **obj)
{
    struct enum_objects *This = impl_from_IEnumObjects(iface);

    TRACE("(%p)->(%s, %p)\n", This, debugstr_guid(riid), obj);

    *obj = NULL;

    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IEnumObjects))
    {
        *obj = &This->IEnumObjects_iface;
    }

    if (*obj)
    {
        IUnknown_AddRef((IUnknown*)*obj);
        return S_OK;
    }

    WARN("no interface for %s.\n", debugstr_guid(riid));

    return E_NOINTERFACE;
}

static ULONG WINAPI enum_objects_AddRef(IEnumObjects *iface)
{
    struct enum_objects *This = impl_from_IEnumObjects(iface);
    ULONG refcount = InterlockedIncrement(&This->ref);

    TRACE("(%p): increasing refcount to %lu.\n", This, refcount);

    return refcount;
}

 static ULONG WINAPI enum_objects_Release(IEnumObjects *iface)
{
    struct enum_objects *This = impl_from_IEnumObjects(iface);
    ULONG refcount = InterlockedDecrement(&This->ref);

    TRACE("(%p): decreasing refcount to %lu.\n", This, refcount);

    if (!refcount)
    {
        free(This);
    }

    return refcount;
}

static HRESULT WINAPI enum_objects_Next(IEnumObjects *iface, ULONG celt, REFIID riid, void **rgelt, ULONG *celtFetched)
{
    struct enum_objects *This = impl_from_IEnumObjects(iface);

    FIXME("(%p %ld, %p)->(%p, %p): stub!\n", This, celt, debugstr_guid(riid), rgelt, celtFetched);

    if (celtFetched)
        *celtFetched = 0;

    return S_FALSE;
}

static HRESULT WINAPI enum_objects_Skip(IEnumObjects *iface, ULONG celt)
{
    struct enum_objects *This = impl_from_IEnumObjects(iface);

    FIXME("(%p %ld): stub!\n", This, celt);

    return E_NOTIMPL;
}

static HRESULT WINAPI enum_objects_Reset(IEnumObjects *iface)
{
    struct enum_objects *This = impl_from_IEnumObjects(iface);

    FIXME("(%p): stub!\n", This);

    return E_NOTIMPL;
}

static HRESULT WINAPI enum_objects_Clone(IEnumObjects *iface, IEnumObjects **ppenum)
{
    struct enum_objects *This = impl_from_IEnumObjects(iface);

    FIXME("(%p)->(%p): stub!\n", This, ppenum);

    return E_NOTIMPL;
}

static const IEnumObjectsVtbl enum_objects_vtbl =
{
    enum_objects_QueryInterface,
    enum_objects_AddRef,
    enum_objects_Release,
    enum_objects_Next,
    enum_objects_Skip,
    enum_objects_Reset,
    enum_objects_Clone,
};

HRESULT WINAPI EnumerableObjectCollection_Constructor(IUnknown *outer, REFIID riid, void **obj)
{
    struct enum_objects *This;
    HRESULT hr;

    TRACE("(%p, %s, %p)\n", outer, debugstr_guid(riid), obj);

    if (outer)
        return CLASS_E_NOAGGREGATION;

    if (!(This = heap_alloc(sizeof(*This))))
        return E_OUTOFMEMORY;

    This->ref = 1;
    This->IEnumObjects_iface.lpVtbl = &enum_objects_vtbl;

    hr = IEnumObjects_QueryInterface(&This->IEnumObjects_iface, riid, obj);
    IEnumObjects_Release(&This->IEnumObjects_iface);
    return hr;
}
