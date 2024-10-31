/*
 * Copyright 2024 Vibhav Pant
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
#include "winstring.h"
#include "roapi.h"

#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#include "windows.foundation.h"

#include "wine/test.h"

static void test_IPropertySet(void)
{
    static const WCHAR *class_name = RuntimeClass_Windows_Foundation_Collections_PropertySet;
    IActivationFactory *factory;
    IInspectable *inspectable;
    IPropertySet *propset;
    IMap_HSTRING_IInspectable *map;
    IMapView_HSTRING_IInspectable *map_view;
    IIterable_IKeyValuePair_HSTRING_IInspectable *iterable;
    IIterator_IKeyValuePair_HSTRING_IInspectable *iterator;
    IObservableMap_HSTRING_IInspectable *observable_map;
    HRESULT hr;
    HSTRING name;

    hr = RoInitialize( RO_INIT_MULTITHREADED );
    ok( SUCCEEDED( hr ), "got %#lx\n", hr );

    hr = WindowsCreateString( class_name, wcslen( class_name ), &name );
    ok( SUCCEEDED( hr ), "got %#lx\n", hr );
    hr = RoGetActivationFactory( name, &IID_IActivationFactory, (void **)&factory );
    WindowsDeleteString( name );
    ok( hr == S_OK || broken( hr == REGDB_E_CLASSNOTREG ),
        "RoGetActivationFactory failed, hr %#lx.\n", hr );
    if (hr == REGDB_E_CLASSNOTREG)
    {
        win_skip( "%s runtimeclass not registered, skipping tests.\n",
                  wine_dbgstr_w( class_name ) );
        RoUninitialize();
        return;
    }

    hr = IActivationFactory_ActivateInstance( factory, &inspectable );
    IActivationFactory_Release( factory );
    todo_wine ok( SUCCEEDED( hr ), "got %#lx\n", hr );
    if (FAILED( hr ))
    {
        skip("could not activate PropertySet instance.\n");
        RoUninitialize();
        return;
    }

    hr = IInspectable_QueryInterface( inspectable, &IID_IPropertySet, (void **)&propset );
    IInspectable_Release( inspectable );
    todo_wine ok( SUCCEEDED( hr ), "QueryInterface failed, got %#lx\n", hr );
    if (FAILED( hr ))
    {
        RoUninitialize();
        return;
    }

    hr = IPropertySet_QueryInterface( propset, &IID_IMap_HSTRING_IInspectable, (void **)&map );
    todo_wine ok( SUCCEEDED( hr ), "QueryInterface failed, got %#lx\n", hr );
    if (FAILED( hr ))
    {
        RoUninitialize();
        return;
    }

    hr = IPropertySet_QueryInterface( propset, &IID_IObservableMap_HSTRING_IInspectable,
                                      (void *)&observable_map );
    IPropertySet_Release( propset );
    todo_wine ok( SUCCEEDED( hr ), "QueryInterface failed, got %#lx\n", hr );

    if (map)
    {
        hr = IMap_HSTRING_IInspectable_QueryInterface( map, &IID_IIterable_IKeyValuePair_HSTRING_IInspectable,
                                                       (void **)&iterable );
        todo_wine ok( SUCCEEDED( hr ), "QueryInterface failed, got %#lx\n", hr );
        if (SUCCEEDED( hr ))
        {
            hr = IIterable_IKeyValuePair_HSTRING_IInspectable_First( iterable, &iterator );
            todo_wine ok( SUCCEEDED( hr ), "got %#lx\n", hr );
            if (SUCCEEDED( hr ))
                IIterator_IKeyValuePair_HSTRING_IInspectable_Release( iterator );
            IIterable_IKeyValuePair_HSTRING_IInspectable_Release( iterable );
        }
        else
            skip( "Could not obtain IIterable<IKeyValuePair<HSTRING, IInspectable *>> instance.\n");

        hr = IMap_HSTRING_IInspectable_GetView( map, &map_view );
        todo_wine ok( SUCCEEDED( hr ), "GetView failed, got %#lx\n", hr );
        if (SUCCEEDED( hr ))
        {

            hr = IMapView_HSTRING_IInspectable_QueryInterface( map_view, &IID_IIterable_IKeyValuePair_HSTRING_IInspectable,
                                                               (void **)&iterable );
            todo_wine ok( SUCCEEDED( hr ), "QueryInterface failed, got %#lx\n", hr );
            if (SUCCEEDED( hr ))
            {

                hr = IIterable_IKeyValuePair_HSTRING_IInspectable_First( iterable, &iterator );
                todo_wine ok( SUCCEEDED( hr ), "got %#lx\n", hr );
                if (SUCCEEDED( hr ))
                    IIterator_IKeyValuePair_HSTRING_IInspectable_Release( iterator );
                IIterable_IKeyValuePair_HSTRING_IInspectable_Release( iterable );
            }
        }
        IMap_HSTRING_IInspectable_Release( map );
    }

    if (observable_map)
        IObservableMap_HSTRING_IInspectable_Release( observable_map );
    RoUninitialize();
}

START_TEST(propertyset)
{
    test_IPropertySet();
}
