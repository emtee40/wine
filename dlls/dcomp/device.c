/*
 * Copyright 2020 Nikolay Sivov for CodeWeavers
 * Copyright 2023 Zhiyi Zhang for CodeWeavers
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

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "initguid.h"
#include "objidl.h"
#include "dcomp_private.h"
#include "dxgi.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(dcomp);

static HRESULT STDMETHODCALLTYPE device_QueryInterface(IDCompositionDevice *iface,
        REFIID iid, void **out)
{
    struct composition_device *device = impl_from_IDCompositionDevice(iface);

    TRACE("iface %p, iid %s, out %p\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_IUnknown)
            || IsEqualGUID(iid, &IID_IDCompositionDevice))
    {
        IUnknown_AddRef(&device->IDCompositionDevice_iface);
        *out = &device->IDCompositionDevice_iface;
        return S_OK;
    }
    else if (device->version >= 2 && IsEqualGUID(iid, &IID_IDCompositionDevice2))
    {
        IUnknown_AddRef(&device->IDCompositionDevice2_iface);
        *out = &device->IDCompositionDevice2_iface;
        return S_OK;
    }

    FIXME("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE device_AddRef(IDCompositionDevice *iface)
{
    struct composition_device *device = impl_from_IDCompositionDevice(iface);
    ULONG ref = InterlockedIncrement(&device->ref);

    TRACE("iface %p, ref %lu.\n", iface, ref);
    return ref;
}

static ULONG STDMETHODCALLTYPE device_Release(IDCompositionDevice *iface)
{
    struct composition_device *device = impl_from_IDCompositionDevice(iface);
    ULONG ref = InterlockedDecrement(&device->ref);

    TRACE("iface %p, ref %lu.\n", iface, ref);

    if (!ref)
        free(device);

    return ref;
}

static HRESULT STDMETHODCALLTYPE device_Commit(IDCompositionDevice *iface)
{
    FIXME("iface %p stub!\n", iface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_WaitForCommitCompletion(IDCompositionDevice *iface)
{
    FIXME("iface %p stub!\n", iface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_GetFrameStatistics(IDCompositionDevice *iface,
        DCOMPOSITION_FRAME_STATISTICS *statistics)
{
    FIXME("iface %p, statistics %p stub!\n", iface, statistics);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateTargetForHwnd(IDCompositionDevice *iface,
        HWND hwnd, BOOL topmost, IDCompositionTarget **target)
{
    FIXME("iface %p, hwnd %p, topmost %d, target %p stub!\n", iface, hwnd, topmost, target);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateVisual(IDCompositionDevice *iface,
        IDCompositionVisual **visual)
{
    FIXME("iface %p, visual %p stub!\n", iface, visual);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateSurface(IDCompositionDevice *iface,
        UINT width, UINT height, DXGI_FORMAT pixel_format, DXGI_ALPHA_MODE alpha_mode,
        IDCompositionSurface **surface)
{
    FIXME("iface %p, width %u, height %u, format %#x, alpha_mode %#x, surface %p stub!\n", iface,
            width, height, pixel_format, alpha_mode, surface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateVirtualSurface(IDCompositionDevice *iface,
        UINT width, UINT height, DXGI_FORMAT pixel_format, DXGI_ALPHA_MODE alpha_mode,
        IDCompositionVirtualSurface **surface)
{
    FIXME("iface %p, width %u, height %u, format %#x, alpha_mode %#x, surface %p stub!\n", iface,
            width, height, pixel_format, alpha_mode, surface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateSurfaceFromHandle(IDCompositionDevice *iface,
        HANDLE handle, IUnknown **surface)
{
    FIXME("iface %p, handle %p, surface %p stub!\n", iface, handle, surface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateSurfaceFromHwnd(IDCompositionDevice *iface,
        HWND hwnd, IUnknown **surface)
{
    FIXME("iface %p, hwnd %p, surface %p stub!\n", iface, hwnd, surface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateTranslateTransform(IDCompositionDevice *iface,
        IDCompositionTranslateTransform **transform)
{
    FIXME("iface %p, transform %p stub!\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateScaleTransform(IDCompositionDevice *iface,
        IDCompositionScaleTransform **transform)
{
    FIXME("iface %p, transform %p stub!\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateRotateTransform(IDCompositionDevice *iface,
        IDCompositionRotateTransform **transform)
{
    FIXME("iface %p, transform %p stub!\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateSkewTransform(IDCompositionDevice *iface,
        IDCompositionSkewTransform **transform)
{
    FIXME("iface %p, transform %p stub!\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateMatrixTransform(IDCompositionDevice *iface,
        IDCompositionMatrixTransform **transform)
{
    FIXME("iface %p, transform %p stub!\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateTransformGroup(IDCompositionDevice *iface,
        IDCompositionTransform **transforms, UINT elements,
        IDCompositionTransform **transform_group)
{
    FIXME("iface %p, transforms %p, elements %u, transform_group %p stub!\n", iface, transforms,
            elements, transform_group);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateTranslateTransform3D(IDCompositionDevice *iface,
        IDCompositionTranslateTransform3D **transform_3d)
{
    FIXME("iface %p, translate_transform_3d %p stub!\n", iface, transform_3d);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateScaleTransform3D(IDCompositionDevice *iface,
        IDCompositionScaleTransform3D **transform_3d)
{
    FIXME("iface %p, transform_3d %p stub!\n", iface, transform_3d);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateRotateTransform3D(IDCompositionDevice *iface,
        IDCompositionRotateTransform3D **transform_3d)
{
    FIXME("iface %p, transform_3d %p stub!\n", iface, transform_3d);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateMatrixTransform3D(IDCompositionDevice *iface,
        IDCompositionMatrixTransform3D **transform_3d)
{
    FIXME("iface %p, transform_3d %p stub!\n", iface, transform_3d);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateTransform3DGroup(IDCompositionDevice *iface,
        IDCompositionTransform3D **transforms_3d, UINT elements,
        IDCompositionTransform3D **transform_3d_group)
{
    FIXME("iface %p, transforms_3d %p, elements %u, transform_3d_group %p stub!\n", iface,
            transforms_3d, elements, transform_3d_group);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateEffectGroup(IDCompositionDevice *iface,
        IDCompositionEffectGroup **effect_group)
{
    FIXME("iface %p, effect_group %p stub!\n", iface, effect_group);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateRectangleClip(IDCompositionDevice *iface,
        IDCompositionRectangleClip **clip)
{
    FIXME("iface %p, clip %p stub!\n", iface, clip);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CreateAnimation(IDCompositionDevice *iface,
        IDCompositionAnimation **animation)
{
    FIXME("iface %p, animation %p stub!\n", iface, animation);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device_CheckDeviceState(IDCompositionDevice *iface,
        BOOL *valid)
{
    FIXME("iface %p, valid %p stub!\n", iface, valid);
    return E_NOTIMPL;
}

static const struct IDCompositionDeviceVtbl device_vtbl =
{
    /* IUnknown methods */
    device_QueryInterface,
    device_AddRef,
    device_Release,
    /* IDCompositionDevice methods */
    device_Commit,
    device_WaitForCommitCompletion,
    device_GetFrameStatistics,
    device_CreateTargetForHwnd,
    device_CreateVisual,
    device_CreateSurface,
    device_CreateVirtualSurface,
    device_CreateSurfaceFromHandle,
    device_CreateSurfaceFromHwnd,
    device_CreateTranslateTransform,
    device_CreateScaleTransform,
    device_CreateRotateTransform,
    device_CreateSkewTransform,
    device_CreateMatrixTransform,
    device_CreateTransformGroup,
    device_CreateTranslateTransform3D,
    device_CreateScaleTransform3D,
    device_CreateRotateTransform3D,
    device_CreateMatrixTransform3D,
    device_CreateTransform3DGroup,
    device_CreateEffectGroup,
    device_CreateRectangleClip,
    device_CreateAnimation,
    device_CheckDeviceState,
};

static HRESULT STDMETHODCALLTYPE device2_QueryInterface(IDCompositionDevice2 *iface,
        REFIID iid, void **out)
{
    struct composition_device *device = impl_from_IDCompositionDevice2(iface);

    TRACE("iface %p.\n", iface);

    return IDCompositionDevice_QueryInterface(&device->IDCompositionDevice_iface, iid, out);
}

static ULONG STDMETHODCALLTYPE device2_AddRef(IDCompositionDevice2 *iface)
{
    struct composition_device *device = impl_from_IDCompositionDevice2(iface);

    TRACE("iface %p.\n", iface);

    return IDCompositionDevice_AddRef(&device->IDCompositionDevice_iface);
}

static ULONG STDMETHODCALLTYPE device2_Release(IDCompositionDevice2 *iface)
{
    struct composition_device *device = impl_from_IDCompositionDevice2(iface);

    TRACE("iface %p.\n", iface);

    return IDCompositionDevice_Release(&device->IDCompositionDevice_iface);
}

static HRESULT STDMETHODCALLTYPE device2_Commit(IDCompositionDevice2 *iface)
{
    FIXME("iface %p stub!\n", iface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_WaitForCommitCompletion(IDCompositionDevice2 *iface)
{
    FIXME("iface %p stub!\n", iface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_GetFrameStatistics(IDCompositionDevice2 *iface,
        DCOMPOSITION_FRAME_STATISTICS *statistics)
{
    FIXME("iface %p, statistics %p stub!\n", iface, statistics);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateVisual(IDCompositionDevice2 *iface,
        IDCompositionVisual2 **visual)
{
    FIXME("iface %p, visual %p stub!\n", iface, visual);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateSurfaceFactory(IDCompositionDevice2 *iface,
        IUnknown *rendering_device, IDCompositionSurfaceFactory **surface_factory)
{
    FIXME("iface %p, rendering_device %p, surface_factory %p stub!\n", iface, rendering_device,
            surface_factory);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateSurface(IDCompositionDevice2 *iface,
        UINT width, UINT height, DXGI_FORMAT pixel_format, DXGI_ALPHA_MODE alpha_mode,
        IDCompositionSurface **surface)
{
    FIXME("iface %p, width %u, height %u, format %#x, alpha_mode %#x, surface %p stub!\n", iface,
            width, height, pixel_format, alpha_mode, surface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateVirtualSurface(IDCompositionDevice2 *iface,
        UINT width, UINT height, DXGI_FORMAT pixel_format, DXGI_ALPHA_MODE alpha_mode,
        IDCompositionVirtualSurface **surface)
{
    FIXME("iface %p, width %u, height %u, format %#x, alpha_mode %#x, surface %p stub!\n", iface,
            width, height, pixel_format, alpha_mode, surface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateTranslateTransform(IDCompositionDevice2 *iface,
        IDCompositionTranslateTransform **transform)
{
    FIXME("iface %p, transform %p stub!\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateScaleTransform(IDCompositionDevice2 *iface,
        IDCompositionScaleTransform **transform)
{
    FIXME("iface %p, transform %p stub!\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateRotateTransform(IDCompositionDevice2 *iface,
        IDCompositionRotateTransform **transform)
{
    FIXME("iface %p, transform %p stub!\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateSkewTransform(IDCompositionDevice2 *iface,
        IDCompositionSkewTransform **transform)
{
    FIXME("iface %p, transform %p stub!\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateMatrixTransform(IDCompositionDevice2 *iface,
        IDCompositionMatrixTransform **transform)
{
    FIXME("iface %p, transform %p stub!\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateTransformGroup(IDCompositionDevice2 *iface,
        IDCompositionTransform **transforms, UINT elements,
        IDCompositionTransform **transform_group)
{
    FIXME("iface %p, transforms %p, elements %u, transform_group %p stub!\n", iface, transforms,
            elements, transform_group);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateTranslateTransform3D(IDCompositionDevice2 *iface,
        IDCompositionTranslateTransform3D **transform_3d)
{
    FIXME("iface %p, translate_transform_3d %p stub!\n", iface, transform_3d);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateScaleTransform3D(IDCompositionDevice2 *iface,
        IDCompositionScaleTransform3D **transform_3d)
{
    FIXME("iface %p, transform_3d %p stub!\n", iface, transform_3d);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateRotateTransform3D(IDCompositionDevice2 *iface,
        IDCompositionRotateTransform3D **transform_3d)
{
    FIXME("iface %p, transform_3d %p stub!\n", iface, transform_3d);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateMatrixTransform3D(IDCompositionDevice2 *iface,
        IDCompositionMatrixTransform3D **transform_3d)
{
    FIXME("iface %p, transform_3d %p stub!\n", iface, transform_3d);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateTransform3DGroup(IDCompositionDevice2 *iface,
        IDCompositionTransform3D **transforms_3d, UINT elements,
        IDCompositionTransform3D **transform_3d_group)
{
    FIXME("iface %p, transforms_3d %p, elements %u, transform_3d_group %p stub!\n", iface,
            transforms_3d, elements, transform_3d_group);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateEffectGroup(IDCompositionDevice2 *iface,
        IDCompositionEffectGroup **effect_group)
{
    FIXME("iface %p, effect_group %p stub!\n", iface, effect_group);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateRectangleClip(IDCompositionDevice2 *iface,
        IDCompositionRectangleClip **clip)
{
    FIXME("iface %p, clip %p stub!\n", iface, clip);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE device2_CreateAnimation(IDCompositionDevice2 *iface,
        IDCompositionAnimation **animation)
{
    FIXME("iface %p, animation %p stub!\n", iface, animation);
    return E_NOTIMPL;
}

static const struct IDCompositionDevice2Vtbl device2_vtbl =
{
    /* IUnknown methods */
    device2_QueryInterface,
    device2_AddRef,
    device2_Release,
    /* IDCompositionDevice2 methods */
    device2_Commit,
    device2_WaitForCommitCompletion,
    device2_GetFrameStatistics,
    device2_CreateVisual,
    device2_CreateSurfaceFactory,
    device2_CreateSurface,
    device2_CreateVirtualSurface,
    device2_CreateTranslateTransform,
    device2_CreateScaleTransform,
    device2_CreateRotateTransform,
    device2_CreateSkewTransform,
    device2_CreateMatrixTransform,
    device2_CreateTransformGroup,
    device2_CreateTranslateTransform3D,
    device2_CreateScaleTransform3D,
    device2_CreateRotateTransform3D,
    device2_CreateMatrixTransform3D,
    device2_CreateTransform3DGroup,
    device2_CreateEffectGroup,
    device2_CreateRectangleClip,
    device2_CreateAnimation,
};

static HRESULT create_device(int version, REFIID iid, void **out)
{
    struct composition_device *device;
    HRESULT hr;

    if (!out)
        return E_INVALIDARG;

    device = calloc(1, sizeof(*device));
    if (!device)
        return E_OUTOFMEMORY;

    device->IDCompositionDevice_iface.lpVtbl = &device_vtbl;
    device->IDCompositionDevice2_iface.lpVtbl = &device2_vtbl;
    device->version = version;
    device->ref = 1;
    hr = IDCompositionDevice_QueryInterface(&device->IDCompositionDevice_iface, iid, out);
    IDCompositionDevice_Release(&device->IDCompositionDevice_iface);
    return hr;
}

HRESULT WINAPI DCompositionCreateDevice(IDXGIDevice *dxgi_device, REFIID iid, void **device)
{
    TRACE("%p, %s, %p\n", dxgi_device, debugstr_guid(iid), device);

    if (!IsEqualIID(iid, &IID_IDCompositionDevice))
        return E_NOINTERFACE;

    return create_device(1, iid, device);
}

HRESULT WINAPI DCompositionCreateDevice2(IUnknown *rendering_device, REFIID iid, void **device)
{
    FIXME("%p, %s, %p semi-stub!\n", rendering_device, debugstr_guid(iid), device);

    if (!IsEqualIID(iid, &IID_IDCompositionDevice))
        return E_NOINTERFACE;

    return create_device(2, iid, device);
}
