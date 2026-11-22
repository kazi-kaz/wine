/*
 * Copyright 2020 Nikolay Sivov for CodeWeavers
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
#include "initguid.h"   /* madeira: before objidl.h so IID_IUnknown (used below) is defined here; dcomp has no uuid import */
#include "objidl.h"
#include "dxgi.h"
#include "dcomp.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(dcomp);

/* iOS-Madeira (godot-composition-swapchain): a pass-through DirectComposition
 * device. Godot 4.5's Direct3D 12 driver binds its swap chain to its window
 * with CreateTargetForHwnd, CreateVisual, Visual::SetContent, Target::SetRoot
 * and Commit, and stops at the first failure. Madeira's dxgi already makes
 * that swap chain for the window itself (DXMT dxgi_factory.cpp,
 * CreateSwapChainForComposition), so these objects only have to say yes.
 * Plain state setters are accepted; everything that would need a real
 * compositor (surfaces, transforms, animations, child visuals) stays E_NOTIMPL.
 * env MADEIRA_DCOMP_PASSTHROUGH=0 keeps the old stub (E_NOTIMPL). */

static BOOL passthrough_enabled(void)
{
    static LONG state; /* 0 = not read, 1 = on, 2 = off */
    if (!state)
    {
        char v[8];
        DWORD n = GetEnvironmentVariableA("MADEIRA_DCOMP_PASSTHROUGH", v, sizeof(v));
        InterlockedExchange(&state, (n == 1 && v[0] == '0') ? 2 : 1);
    }
    return state == 1;
}

/* ---- visual ---------------------------------------------------------- */

struct visual
{
    IDCompositionVisual IDCompositionVisual_iface;
    LONG refcount;
    IUnknown *content;
};

static inline struct visual *impl_from_IDCompositionVisual(IDCompositionVisual *iface)
{
    return CONTAINING_RECORD(iface, struct visual, IDCompositionVisual_iface);
}

static HRESULT WINAPI visual_QueryInterface(IDCompositionVisual *iface, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IDCompositionVisual) || IsEqualGUID(iid, &IID_IUnknown))
    {
        IDCompositionVisual_AddRef(iface);
        *out = iface;
        return S_OK;
    }
    WARN("%s not implemented.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI visual_AddRef(IDCompositionVisual *iface)
{
    return InterlockedIncrement(&impl_from_IDCompositionVisual(iface)->refcount);
}

static ULONG WINAPI visual_Release(IDCompositionVisual *iface)
{
    struct visual *visual = impl_from_IDCompositionVisual(iface);
    ULONG refcount = InterlockedDecrement(&visual->refcount);
    if (!refcount)
    {
        free(visual);
    }
    return refcount;
}

#define VISUAL_NOTIMPL(name, args) \
    static HRESULT WINAPI visual_##name args { FIXME("%p: " #name " not implemented.\n", iface); return E_NOTIMPL; }

VISUAL_NOTIMPL(SetOffsetXAnimation, (IDCompositionVisual *iface, IDCompositionAnimation *a))
VISUAL_NOTIMPL(SetOffsetYAnimation, (IDCompositionVisual *iface, IDCompositionAnimation *a))
VISUAL_NOTIMPL(SetTransformObject, (IDCompositionVisual *iface, IDCompositionTransform *t))
VISUAL_NOTIMPL(SetTransformParent, (IDCompositionVisual *iface, IDCompositionVisual *v))
VISUAL_NOTIMPL(SetEffect, (IDCompositionVisual *iface, IDCompositionEffect *e))
VISUAL_NOTIMPL(SetClipObject, (IDCompositionVisual *iface, IDCompositionClip *c))
VISUAL_NOTIMPL(AddVisual, (IDCompositionVisual *iface, IDCompositionVisual *v, BOOL above, IDCompositionVisual *ref))
VISUAL_NOTIMPL(RemoveVisual, (IDCompositionVisual *iface, IDCompositionVisual *v))
VISUAL_NOTIMPL(RemoveAllVisuals, (IDCompositionVisual *iface))

/* Plain state setters: nothing composites here, so accepting them is harmless. */
static HRESULT WINAPI visual_SetOffsetX(IDCompositionVisual *iface, float x) { return S_OK; }
static HRESULT WINAPI visual_SetOffsetY(IDCompositionVisual *iface, float y) { return S_OK; }
static HRESULT WINAPI visual_SetTransform(IDCompositionVisual *iface, const D2D_MATRIX_3X2_F *m) { return S_OK; }
static HRESULT WINAPI visual_SetBitmapInterpolationMode(IDCompositionVisual *iface,
        enum DCOMPOSITION_BITMAP_INTERPOLATION_MODE mode) { return S_OK; }
static HRESULT WINAPI visual_SetBorderMode(IDCompositionVisual *iface, enum DCOMPOSITION_BORDER_MODE mode) { return S_OK; }
static HRESULT WINAPI visual_SetClip(IDCompositionVisual *iface, const D2D_RECT_F *rect) { return S_OK; }
static HRESULT WINAPI visual_SetCompositeMode(IDCompositionVisual *iface, enum DCOMPOSITION_COMPOSITE_MODE mode) { return S_OK; }

static HRESULT WINAPI visual_SetContent(IDCompositionVisual *iface, IUnknown *content)
{
    struct visual *visual = impl_from_IDCompositionVisual(iface);
    static LONG said;

    if (InterlockedIncrement(&said) <= 4)
        ERR("[dcomp-passthrough] visual %p content %p (the swap chain already presents to its window)\n",
            iface, content);
    /* Not referenced: nothing reads it, and holding the swap chain would keep
     * an old one alive on the window after Godot recreates it on resize. */
    visual->content = content;
    return S_OK;
}

static const IDCompositionVisualVtbl visual_vtbl =
{
    .QueryInterface = visual_QueryInterface,
    .AddRef = visual_AddRef,
    .Release = visual_Release,
    .SetOffsetXAnimation = visual_SetOffsetXAnimation,
    .SetOffsetX = visual_SetOffsetX,
    .SetOffsetYAnimation = visual_SetOffsetYAnimation,
    .SetOffsetY = visual_SetOffsetY,
    .SetTransformObject = visual_SetTransformObject,
    .SetTransform = visual_SetTransform,
    .SetTransformParent = visual_SetTransformParent,
    .SetEffect = visual_SetEffect,
    .SetBitmapInterpolationMode = visual_SetBitmapInterpolationMode,
    .SetBorderMode = visual_SetBorderMode,
    .SetClipObject = visual_SetClipObject,
    .SetClip = visual_SetClip,
    .SetContent = visual_SetContent,
    .AddVisual = visual_AddVisual,
    .RemoveVisual = visual_RemoveVisual,
    .RemoveAllVisuals = visual_RemoveAllVisuals,
    .SetCompositeMode = visual_SetCompositeMode,
};

/* ---- target ---------------------------------------------------------- */

struct target
{
    IDCompositionTarget IDCompositionTarget_iface;
    LONG refcount;
    HWND hwnd;
    IDCompositionVisual *root;
};

static inline struct target *impl_from_IDCompositionTarget(IDCompositionTarget *iface)
{
    return CONTAINING_RECORD(iface, struct target, IDCompositionTarget_iface);
}

static HRESULT WINAPI target_QueryInterface(IDCompositionTarget *iface, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IDCompositionTarget) || IsEqualGUID(iid, &IID_IUnknown))
    {
        IDCompositionTarget_AddRef(iface);
        *out = iface;
        return S_OK;
    }
    WARN("%s not implemented.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI target_AddRef(IDCompositionTarget *iface)
{
    return InterlockedIncrement(&impl_from_IDCompositionTarget(iface)->refcount);
}

static ULONG WINAPI target_Release(IDCompositionTarget *iface)
{
    struct target *target = impl_from_IDCompositionTarget(iface);
    ULONG refcount = InterlockedDecrement(&target->refcount);
    if (!refcount)
    {
        if (target->root) IDCompositionVisual_Release(target->root);
        free(target);
    }
    return refcount;
}

static HRESULT WINAPI target_SetRoot(IDCompositionTarget *iface, IDCompositionVisual *visual)
{
    struct target *target = impl_from_IDCompositionTarget(iface);

    TRACE("%p, %p (hwnd %p).\n", iface, visual, target->hwnd);
    if (visual) IDCompositionVisual_AddRef(visual);
    if (target->root) IDCompositionVisual_Release(target->root);
    target->root = visual;
    return S_OK;
}

static const IDCompositionTargetVtbl target_vtbl =
{
    .QueryInterface = target_QueryInterface,
    .AddRef = target_AddRef,
    .Release = target_Release,
    .SetRoot = target_SetRoot,
};

/* ---- device ---------------------------------------------------------- */

struct device
{
    IDCompositionDevice IDCompositionDevice_iface;
    LONG refcount;
};

static inline struct device *impl_from_IDCompositionDevice(IDCompositionDevice *iface)
{
    return CONTAINING_RECORD(iface, struct device, IDCompositionDevice_iface);
}

static HRESULT WINAPI device_QueryInterface(IDCompositionDevice *iface, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IDCompositionDevice) || IsEqualGUID(iid, &IID_IUnknown))
    {
        IDCompositionDevice_AddRef(iface);
        *out = iface;
        return S_OK;
    }
    WARN("%s not implemented.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI device_AddRef(IDCompositionDevice *iface)
{
    return InterlockedIncrement(&impl_from_IDCompositionDevice(iface)->refcount);
}

static ULONG WINAPI device_Release(IDCompositionDevice *iface)
{
    struct device *device = impl_from_IDCompositionDevice(iface);
    ULONG refcount = InterlockedDecrement(&device->refcount);
    if (!refcount) free(device);
    return refcount;
}

static HRESULT WINAPI device_Commit(IDCompositionDevice *iface) { return S_OK; }
static HRESULT WINAPI device_WaitForCommitCompletion(IDCompositionDevice *iface) { return S_OK; }

static HRESULT WINAPI device_CheckDeviceState(IDCompositionDevice *iface, BOOL *valid)
{
    if (!valid) return E_INVALIDARG;
    *valid = TRUE;
    return S_OK;
}

static HRESULT WINAPI device_CreateTargetForHwnd(IDCompositionDevice *iface, HWND hwnd, BOOL topmost,
        IDCompositionTarget **out)
{
    struct target *target;

    TRACE("%p, %p, %d, %p.\n", iface, hwnd, topmost, out);
    if (!out) return E_INVALIDARG;
    *out = NULL;
    if (!(target = calloc(1, sizeof(*target)))) return E_OUTOFMEMORY;
    target->IDCompositionTarget_iface.lpVtbl = &target_vtbl;
    target->refcount = 1;
    target->hwnd = hwnd;
    *out = &target->IDCompositionTarget_iface;
    return S_OK;
}

static HRESULT WINAPI device_CreateVisual(IDCompositionDevice *iface, IDCompositionVisual **out)
{
    struct visual *visual;

    TRACE("%p, %p.\n", iface, out);
    if (!out) return E_INVALIDARG;
    *out = NULL;
    if (!(visual = calloc(1, sizeof(*visual)))) return E_OUTOFMEMORY;
    visual->IDCompositionVisual_iface.lpVtbl = &visual_vtbl;
    visual->refcount = 1;
    *out = &visual->IDCompositionVisual_iface;
    return S_OK;
}

#define DEVICE_NOTIMPL(name, args) \
    static HRESULT WINAPI device_##name args { FIXME("%p: " #name " not implemented.\n", iface); return E_NOTIMPL; }

DEVICE_NOTIMPL(GetFrameStatistics, (IDCompositionDevice *iface, DCOMPOSITION_FRAME_STATISTICS *s))
DEVICE_NOTIMPL(CreateSurface, (IDCompositionDevice *iface, UINT w, UINT h, DXGI_FORMAT f, DXGI_ALPHA_MODE a,
        IDCompositionSurface **s))
DEVICE_NOTIMPL(CreateVirtualSurface, (IDCompositionDevice *iface, UINT w, UINT h, DXGI_FORMAT f, DXGI_ALPHA_MODE a,
        IDCompositionVirtualSurface **s))
DEVICE_NOTIMPL(CreateSurfaceFromHandle, (IDCompositionDevice *iface, HANDLE handle, IUnknown **s))
DEVICE_NOTIMPL(CreateSurfaceFromHwnd, (IDCompositionDevice *iface, HWND hwnd, IUnknown **s))
DEVICE_NOTIMPL(CreateTranslateTransform, (IDCompositionDevice *iface, IDCompositionTranslateTransform **t))
DEVICE_NOTIMPL(CreateScaleTransform, (IDCompositionDevice *iface, IDCompositionScaleTransform **t))
DEVICE_NOTIMPL(CreateRotateTransform, (IDCompositionDevice *iface, IDCompositionRotateTransform **t))
DEVICE_NOTIMPL(CreateSkewTransform, (IDCompositionDevice *iface, IDCompositionSkewTransform **t))
DEVICE_NOTIMPL(CreateMatrixTransform, (IDCompositionDevice *iface, IDCompositionMatrixTransform **t))
DEVICE_NOTIMPL(CreateTransformGroup, (IDCompositionDevice *iface, IDCompositionTransform **ts, UINT n,
        IDCompositionTransform **g))
DEVICE_NOTIMPL(CreateTranslateTransform3D, (IDCompositionDevice *iface, IDCompositionTranslateTransform3D **t))
DEVICE_NOTIMPL(CreateScaleTransform3D, (IDCompositionDevice *iface, IDCompositionScaleTransform3D **t))
DEVICE_NOTIMPL(CreateRotateTransform3D, (IDCompositionDevice *iface, IDCompositionRotateTransform3D **t))
DEVICE_NOTIMPL(CreateMatrixTransform3D, (IDCompositionDevice *iface, IDCompositionMatrixTransform3D **t))
DEVICE_NOTIMPL(CreateTransform3DGroup, (IDCompositionDevice *iface, IDCompositionTransform3D **ts, UINT n,
        IDCompositionTransform3D **g))
DEVICE_NOTIMPL(CreateEffectGroup, (IDCompositionDevice *iface, IDCompositionEffectGroup **g))
DEVICE_NOTIMPL(CreateRectangleClip, (IDCompositionDevice *iface, IDCompositionRectangleClip **c))
DEVICE_NOTIMPL(CreateAnimation, (IDCompositionDevice *iface, IDCompositionAnimation **a))

static const IDCompositionDeviceVtbl device_vtbl =
{
    .QueryInterface = device_QueryInterface,
    .AddRef = device_AddRef,
    .Release = device_Release,
    .Commit = device_Commit,
    .WaitForCommitCompletion = device_WaitForCommitCompletion,
    .GetFrameStatistics = device_GetFrameStatistics,
    .CreateTargetForHwnd = device_CreateTargetForHwnd,
    .CreateVisual = device_CreateVisual,
    .CreateSurface = device_CreateSurface,
    .CreateVirtualSurface = device_CreateVirtualSurface,
    .CreateSurfaceFromHandle = device_CreateSurfaceFromHandle,
    .CreateSurfaceFromHwnd = device_CreateSurfaceFromHwnd,
    .CreateTranslateTransform = device_CreateTranslateTransform,
    .CreateScaleTransform = device_CreateScaleTransform,
    .CreateRotateTransform = device_CreateRotateTransform,
    .CreateSkewTransform = device_CreateSkewTransform,
    .CreateMatrixTransform = device_CreateMatrixTransform,
    .CreateTransformGroup = device_CreateTransformGroup,
    .CreateTranslateTransform3D = device_CreateTranslateTransform3D,
    .CreateScaleTransform3D = device_CreateScaleTransform3D,
    .CreateRotateTransform3D = device_CreateRotateTransform3D,
    .CreateMatrixTransform3D = device_CreateMatrixTransform3D,
    .CreateTransform3DGroup = device_CreateTransform3DGroup,
    .CreateEffectGroup = device_CreateEffectGroup,
    .CreateRectangleClip = device_CreateRectangleClip,
    .CreateAnimation = device_CreateAnimation,
    .CheckDeviceState = device_CheckDeviceState,
};

HRESULT WINAPI DCompositionCreateDevice(IDXGIDevice *dxgi_device, REFIID iid, void **out)
{
    static LONG create_said;
    struct device *device;
    HRESULT hr;

    TRACE("%p, %s, %p.\n", dxgi_device, debugstr_guid(iid), out);

    if (!passthrough_enabled())
    {
        FIXME("%p, %s, %p (env MADEIRA_DCOMP_PASSTHROUGH=0).\n", dxgi_device, debugstr_guid(iid), out);
        return E_NOTIMPL;
    }
    if (!out) return E_INVALIDARG;
    *out = NULL;
    if (!(device = calloc(1, sizeof(*device)))) return E_OUTOFMEMORY;
    device->IDCompositionDevice_iface.lpVtbl = &device_vtbl;
    device->refcount = 1;
    hr = IDCompositionDevice_QueryInterface(&device->IDCompositionDevice_iface, iid, out);
    IDCompositionDevice_Release(&device->IDCompositionDevice_iface);
    if (InterlockedIncrement(&create_said) <= 4)
        ERR("[dcomp-passthrough] DCompositionCreateDevice(%s) -> %#lx (env MADEIRA_DCOMP_PASSTHROUGH=0 turns this off)\n",
            debugstr_guid(iid), hr);
    return hr;
}

HRESULT WINAPI DCompositionCreateDevice2(IUnknown *rendering_device, REFIID iid, void **device)
{
    FIXME("%p, %s, %p.\n", rendering_device, debugstr_guid(iid), device);

    return E_NOTIMPL;
}

HRESULT WINAPI DCompositionCreateDevice3(IUnknown *rendering_device, REFIID iid, void **device)
{
    FIXME("%p, %s, %p.\n", rendering_device, debugstr_guid(iid), device);

    return E_NOTIMPL;
}
