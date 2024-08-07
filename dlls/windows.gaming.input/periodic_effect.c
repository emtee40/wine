/* WinRT Windows.Gaming.Input implementation
 *
 * Copyright 2022 Rémi Bernon for CodeWeavers
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

#include "private.h"
#include "provider.h"

WINE_DEFAULT_DEBUG_CHANNEL(input);

struct periodic_effect
{
    IPeriodicForceEffect IPeriodicForceEffect_iface;
    IWineForceFeedbackEffectImpl *IWineForceFeedbackEffectImpl_inner;
    const WCHAR *class_name;
    LONG refcount;

    PeriodicForceEffectKind kind;
};

INTERFACE_IMPL_FROM( periodic_effect, IPeriodicForceEffect );

static HRESULT WINAPI periodic_effect_QueryInterface( IPeriodicForceEffect *iface, REFIID iid, void **out )
{
    struct periodic_effect *impl = periodic_effect_from_IPeriodicForceEffect( iface );
    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid( iid ), out );
    QUERY_INTERFACE_IPeriodicForceEffect( impl, iid, out, IPeriodicForceEffect_iface )
    return IWineForceFeedbackEffectImpl_QueryInterface( impl->IWineForceFeedbackEffectImpl_inner, iid, out );
}

IUNKNOWN_IMPL_ADDREF( periodic_effect, IPeriodicForceEffect );

static void periodic_effect_destroy( struct periodic_effect *impl )
{
    IWineForceFeedbackEffectImpl_Release( impl->IWineForceFeedbackEffectImpl_inner );
    free( impl );
}

IUNKNOWN_IMPL_RELEASE( periodic_effect, IPeriodicForceEffect );
IINSPECTABLE_IMPL( periodic_effect, IPeriodicForceEffect );

static HRESULT WINAPI periodic_effect_get_Kind( IPeriodicForceEffect *iface, PeriodicForceEffectKind *kind )
{
    struct periodic_effect *impl = periodic_effect_from_IPeriodicForceEffect( iface );
    TRACE( "iface %p, kind %p.\n", iface, kind );
    *kind = impl->kind;
    return S_OK;
}

static HRESULT WINAPI periodic_effect_SetParameters( IPeriodicForceEffect *iface, Vector3 direction, FLOAT frequency, FLOAT phase,
                                            FLOAT bias, TimeSpan duration )
{
    struct periodic_effect *impl = periodic_effect_from_IPeriodicForceEffect( iface );
    WineForceFeedbackEffectParameters params =
    {
        .periodic =
        {
            .type = WineForceFeedbackEffectType_Periodic_SquareWave + impl->kind,
            .direction = direction,
            .frequency = frequency,
            .phase = phase,
            .bias = bias,
            .duration = duration,
            .repeat_count = 1,
            .gain = 1.,
        },
    };

    TRACE( "iface %p, direction %s, frequency %f, phase %f, bias %f, duration %I64u.\n", iface,
           debugstr_vector3( &direction ), frequency, phase, bias, duration.Duration );

    return IWineForceFeedbackEffectImpl_put_Parameters( impl->IWineForceFeedbackEffectImpl_inner, params, NULL );
}

static HRESULT WINAPI periodic_effect_SetParametersWithEnvelope( IPeriodicForceEffect *iface, Vector3 direction, FLOAT frequency, FLOAT phase, FLOAT bias,
                                                        FLOAT attack_gain, FLOAT sustain_gain, FLOAT release_gain, TimeSpan start_delay,
                                                        TimeSpan attack_duration, TimeSpan sustain_duration,
                                                        TimeSpan release_duration, UINT32 repeat_count )
{
    struct periodic_effect *impl = periodic_effect_from_IPeriodicForceEffect( iface );
    WineForceFeedbackEffectParameters params =
    {
        .periodic =
        {
            .type = WineForceFeedbackEffectType_Periodic_SquareWave + impl->kind,
            .direction = direction,
            .frequency = frequency,
            .phase = phase,
            .bias = bias,
            .duration = {attack_duration.Duration + sustain_duration.Duration + release_duration.Duration},
            .start_delay = start_delay,
            .repeat_count = repeat_count,
            .gain = sustain_gain,
        },
    };
    WineForceFeedbackEffectEnvelope envelope =
    {
        .attack_gain = attack_gain,
        .release_gain = release_gain,
        .attack_duration = attack_duration,
        .release_duration = release_duration,
    };

    TRACE( "iface %p, direction %s, frequency %f, phase %f, bias %f, attack_gain %f, sustain_gain %f, release_gain %f, start_delay %I64u, "
           "attack_duration %I64u, sustain_duration %I64u, release_duration %I64u, repeat_count %u.\n", iface, debugstr_vector3( &direction ),
           frequency, phase, bias, attack_gain, sustain_gain, release_gain, start_delay.Duration, attack_duration.Duration, sustain_duration.Duration,
           release_duration.Duration, repeat_count );

    return IWineForceFeedbackEffectImpl_put_Parameters( impl->IWineForceFeedbackEffectImpl_inner, params, &envelope );
}

INTERFACE_VTBL_IPeriodicForceEffect( periodic_effect );

struct periodic_factory
{
    IActivationFactory IActivationFactory_iface;
    IPeriodicForceEffectFactory IPeriodicForceEffectFactory_iface;
    IAgileObject IAgileObject_iface;
    const WCHAR *class_name;
};

INTERFACE_IMPL_STATIC_IActivationFactory( periodic_factory, IPeriodicForceEffectFactory, IAgileObject, END )

static HRESULT WINAPI periodic_factory_ActivateInstance( IActivationFactory *iface, IInspectable **instance )
{
    FIXME( "iface %p, instance %p stub!\n", iface, instance );
    return E_NOTIMPL;
}

INTERFACE_VTBL_IActivationFactory( periodic_factory );

static HRESULT WINAPI periodic_factory_IPeriodicForceEffectFactory_CreateInstance( IPeriodicForceEffectFactory *iface, enum PeriodicForceEffectKind kind, IForceFeedbackEffect **out )
{
    enum WineForceFeedbackEffectType type = WineForceFeedbackEffectType_Periodic + kind;
    struct periodic_effect *impl;
    HRESULT hr;

    TRACE( "iface %p, kind %u, out %p.\n", iface, kind, out );

    if (!(impl = calloc( 1, sizeof(struct periodic_effect) ))) return E_OUTOFMEMORY;
    impl->IPeriodicForceEffect_iface.lpVtbl = &periodic_effect_vtbl;
    impl->class_name = RuntimeClass_Windows_Gaming_Input_ForceFeedback_PeriodicForceEffect;
    impl->refcount = 1;
    impl->kind = kind;

    if (FAILED(hr = force_feedback_effect_create( type, (IInspectable *)&impl->IPeriodicForceEffect_iface, &impl->IWineForceFeedbackEffectImpl_inner )) ||
        FAILED(hr = IPeriodicForceEffect_QueryInterface( &impl->IPeriodicForceEffect_iface, &IID_IForceFeedbackEffect, (void **)out )))
    {
        if (impl->IWineForceFeedbackEffectImpl_inner) IWineForceFeedbackEffectImpl_Release( impl->IWineForceFeedbackEffectImpl_inner );
        free( impl );
        return hr;
    }

    IPeriodicForceEffect_Release( &impl->IPeriodicForceEffect_iface );
    TRACE( "created PeriodicForceEffect %p\n", *out );
    return S_OK;
}

INTERFACE_VTBL_IPeriodicForceEffectFactory( periodic_factory_IPeriodicForceEffectFactory );
INTERFACE_VTBL_IAgileObject( periodic_factory_IAgileObject );

static struct periodic_factory periodic_statics =
{
    {&periodic_factory_vtbl},
    {&periodic_factory_IPeriodicForceEffectFactory_vtbl},
    {&periodic_factory_IAgileObject_vtbl},
    RuntimeClass_Windows_Gaming_Input_ForceFeedback_PeriodicForceEffect,
};

IInspectable *periodic_effect_factory = (IInspectable *)&periodic_statics.IActivationFactory_iface;
