/*
 * Mount manager service implementation
 *
 * Copyright 2008 Alexandre Julliard
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

#include "config.h"

#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#define NONAMELESSUNION

#include "mountmgr.h"
#include "winreg.h"
#include "unixlib.h"
#include "wine/list.h"
#include "wine/unicode.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(mountmgr);

#define MIN_ID_LEN     4

struct mount_point
{
    struct list    entry;   /* entry in mount points list */
    DEVICE_OBJECT *device;  /* disk device */
    UNICODE_STRING name;    /* device name */
    UNICODE_STRING link;    /* DOS device symlink */
    void          *id;      /* device unique id */
    unsigned int   id_len;
};

static struct list mount_points_list = LIST_INIT(mount_points_list);
static HKEY mount_key;

void set_mount_point_id( struct mount_point *mount, const void *id, unsigned int id_len )
{
    RtlFreeHeap( GetProcessHeap(), 0, mount->id );
    mount->id_len = max( MIN_ID_LEN, id_len );
    if ((mount->id = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, mount->id_len )))
    {
        memcpy( mount->id, id, id_len );
        RegSetValueExW( mount_key, mount->link.Buffer, 0, REG_BINARY, mount->id, mount->id_len );
    }
    else mount->id_len = 0;
}

static struct mount_point *add_mount_point( DEVICE_OBJECT *device, UNICODE_STRING *device_name,
                                            const WCHAR *link )
{
    struct mount_point *mount;
    WCHAR *str;
    UINT len = (strlenW(link) + 1) * sizeof(WCHAR) + device_name->Length + sizeof(WCHAR);

    if (!(mount = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*mount) + len ))) return NULL;

    str = (WCHAR *)(mount + 1);
    strcpyW( str, link );
    RtlInitUnicodeString( &mount->link, str );
    str += strlenW(str) + 1;
    memcpy( str, device_name->Buffer, device_name->Length );
    str[device_name->Length / sizeof(WCHAR)] = 0;
    mount->name.Buffer = str;
    mount->name.Length = device_name->Length;
    mount->name.MaximumLength = device_name->Length + sizeof(WCHAR);
    mount->device = device;
    mount->id = NULL;
    list_add_tail( &mount_points_list, &mount->entry );

    IoCreateSymbolicLink( &mount->link, device_name );

    TRACE( "created %s id %s for %s\n", debugstr_w(mount->link.Buffer),
           debugstr_a(mount->id), debugstr_w(mount->name.Buffer) );
    return mount;
}

/* create the DosDevices mount point symlink for a new device */
struct mount_point *add_dosdev_mount_point( DEVICE_OBJECT *device, UNICODE_STRING *device_name, int drive )
{
    static const WCHAR driveW[] = {'\\','D','o','s','D','e','v','i','c','e','s','\\','%','c',':',0};
    WCHAR link[sizeof(driveW)];

    sprintfW( link, driveW, 'A' + drive );
    return add_mount_point( device, device_name, link );
}

/* create the Volume mount point symlink for a new device */
struct mount_point *add_volume_mount_point( DEVICE_OBJECT *device, UNICODE_STRING *device_name,
                                            const GUID *guid )
{
    static const WCHAR volumeW[] = {'\\','?','?','\\','V','o','l','u','m','e','{',
                                    '%','0','8','x','-','%','0','4','x','-','%','0','4','x','-',
                                    '%','0','2','x','%','0','2','x','-','%','0','2','x','%','0','2','x',
                                    '%','0','2','x','%','0','2','x','%','0','2','x','%','0','2','x','}',0};
    WCHAR link[sizeof(volumeW)];

    sprintfW( link, volumeW, guid->Data1, guid->Data2, guid->Data3,
              guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
              guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    return add_mount_point( device, device_name, link );
}

/* delete the mount point symlinks when a device goes away */
void delete_mount_point( struct mount_point *mount )
{
    TRACE( "deleting %s\n", debugstr_w(mount->link.Buffer) );
    list_remove( &mount->entry );
    RegDeleteValueW( mount_key, mount->link.Buffer );
    IoDeleteSymbolicLink( &mount->link );
    RtlFreeHeap( GetProcessHeap(), 0, mount->id );
    RtlFreeHeap( GetProcessHeap(), 0, mount );
}

/* check if a given mount point matches the requested specs */
static BOOL matching_mount_point( const struct mount_point *mount, const MOUNTMGR_MOUNT_POINT *spec )
{
    if (spec->SymbolicLinkNameOffset)
    {
        const WCHAR *name = (const WCHAR *)((const char *)spec + spec->SymbolicLinkNameOffset);
        if (spec->SymbolicLinkNameLength != mount->link.Length) return FALSE;
        if (strncmpiW( name, mount->link.Buffer, mount->link.Length/sizeof(WCHAR)))
            return FALSE;
    }
    if (spec->DeviceNameOffset)
    {
        const WCHAR *name = (const WCHAR *)((const char *)spec + spec->DeviceNameOffset);
        if (spec->DeviceNameLength != mount->name.Length) return FALSE;
        if (strncmpiW( name, mount->name.Buffer, mount->name.Length/sizeof(WCHAR)))
            return FALSE;
    }
    if (spec->UniqueIdOffset)
    {
        const void *id = ((const char *)spec + spec->UniqueIdOffset);
        if (spec->UniqueIdLength != mount->id_len) return FALSE;
        if (memcmp( id, mount->id, mount->id_len )) return FALSE;
    }
    return TRUE;
}

/* implementation of IOCTL_MOUNTMGR_QUERY_POINTS */
static NTSTATUS query_mount_points( void *buff, SIZE_T insize,
                                    SIZE_T outsize, IO_STATUS_BLOCK *iosb )
{
    UINT count, pos, size;
    MOUNTMGR_MOUNT_POINT *input = buff;
    MOUNTMGR_MOUNT_POINTS *info;
    struct mount_point *mount;

    if (insize < sizeof(*input) ||
        outsize < sizeof(*info) ||
        input->SymbolicLinkNameOffset + input->SymbolicLinkNameLength > insize ||
        input->UniqueIdOffset + input->UniqueIdLength > insize ||
        input->DeviceNameOffset + input->DeviceNameLength > insize ||
        input->SymbolicLinkNameOffset + input->SymbolicLinkNameLength < input->SymbolicLinkNameOffset ||
        input->UniqueIdOffset + input->UniqueIdLength < input->UniqueIdOffset ||
        input->DeviceNameOffset + input->DeviceNameLength < input->DeviceNameOffset)
        return STATUS_INVALID_PARAMETER;

    count = size = 0;
    LIST_FOR_EACH_ENTRY( mount, &mount_points_list, struct mount_point, entry )
    {
        if (!matching_mount_point( mount, input )) continue;
        size += mount->name.Length;
        size += mount->link.Length;
        size += mount->id_len;
        size = (size + sizeof(WCHAR) - 1) & ~(sizeof(WCHAR) - 1);
        count++;
    }
    pos = FIELD_OFFSET( MOUNTMGR_MOUNT_POINTS, MountPoints[count] );
    size += pos;

    if (size > outsize)
    {
        info = buff;
        info->Size = size;
        iosb->Information = sizeof(info->Size);
        return STATUS_BUFFER_OVERFLOW;
    }

    input = HeapAlloc( GetProcessHeap(), 0, insize );
    if (!input)
        return STATUS_NO_MEMORY;
    memcpy( input, buff, insize );
    info = buff;

    info->NumberOfMountPoints = count;
    count = 0;
    LIST_FOR_EACH_ENTRY( mount, &mount_points_list, struct mount_point, entry )
    {
        if (!matching_mount_point( mount, input )) continue;

        info->MountPoints[count].DeviceNameOffset = pos;
        info->MountPoints[count].DeviceNameLength = mount->name.Length;
        memcpy( (char *)buff + pos, mount->name.Buffer, mount->name.Length );
        pos += mount->name.Length;

        info->MountPoints[count].SymbolicLinkNameOffset = pos;
        info->MountPoints[count].SymbolicLinkNameLength = mount->link.Length;
        memcpy( (char *)buff + pos, mount->link.Buffer, mount->link.Length );
        pos += mount->link.Length;

        info->MountPoints[count].UniqueIdOffset = pos;
        info->MountPoints[count].UniqueIdLength = mount->id_len;
        memcpy( (char *)buff + pos, mount->id, mount->id_len );
        pos += mount->id_len;
        pos = (pos + sizeof(WCHAR) - 1) & ~(sizeof(WCHAR) - 1);
        count++;
    }
    info->Size = pos;
    iosb->Information = pos;
    HeapFree( GetProcessHeap(), 0, input );
    return STATUS_SUCCESS;
}

/* implementation of IOCTL_MOUNTMGR_DEFINE_UNIX_DRIVE */
static NTSTATUS define_unix_drive( const void *in_buff, SIZE_T insize )
{
    const struct mountmgr_unix_drive *input = in_buff;
    const char *mount_point = NULL, *device = NULL;
    WCHAR letter = tolowerW( input->letter );

    if (letter < 'a' || letter > 'z') return STATUS_INVALID_PARAMETER;
    if (input->type > DRIVE_RAMDISK) return STATUS_INVALID_PARAMETER;
    if (input->mount_point_offset > insize || input->device_offset > insize)
        return STATUS_INVALID_PARAMETER;

    /* make sure string are null-terminated */
    if (input->mount_point_offset)
    {
        mount_point = (const char *)in_buff + input->mount_point_offset;
        if (!memchr( mount_point, 0, insize - input->mount_point_offset )) return STATUS_INVALID_PARAMETER;
    }
    if (input->device_offset)
    {
        device = (const char *)in_buff + input->device_offset;
        if (!memchr( device, 0, insize - input->device_offset )) return STATUS_INVALID_PARAMETER;
    }

    if (input->type != DRIVE_NO_ROOT_DIR)
    {
        enum device_type type = DEVICE_UNKNOWN;

        TRACE( "defining %c: dev %s mount %s type %u\n",
               letter, debugstr_a(device), debugstr_a(mount_point), input->type );
        switch (input->type)
        {
        case DRIVE_REMOVABLE: type = (letter >= 'c') ? DEVICE_HARDDISK : DEVICE_FLOPPY; break;
        case DRIVE_REMOTE:    type = DEVICE_NETWORK; break;
        case DRIVE_CDROM:     type = DEVICE_CDROM; break;
        case DRIVE_RAMDISK:   type = DEVICE_RAMDISK; break;
        case DRIVE_FIXED:     type = DEVICE_HARDDISK_VOL; break;
        }
        return add_dos_device( letter - 'a', NULL, device, mount_point, type, NULL, NULL );
    }
    else
    {
        TRACE( "removing %c:\n", letter );
        return remove_dos_device( letter - 'a', NULL );
    }
}

/* implementation of IOCTL_MOUNTMGR_DEFINE_SHELL_FOLDER */
static NTSTATUS define_shell_folder( const void *in_buff, SIZE_T insize )
{
    const struct mountmgr_shell_folder *input = in_buff;
    const char *link = NULL;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    NTSTATUS status;
    ULONG size = 256;
    char *buffer = NULL, *backup = NULL;

    if (input->folder_offset >= insize || input->folder_size > insize - input->folder_offset ||
        input->symlink_offset >= insize)
        return STATUS_INVALID_PARAMETER;

    /* make sure string is null-terminated */
    if (input->symlink_offset)
    {
        link = (const char *)in_buff + input->symlink_offset;
        if (!memchr( link, 0, insize - input->symlink_offset )) return STATUS_INVALID_PARAMETER;
        if (!link[0]) link = NULL;
    }

    name.Buffer = (WCHAR *)((char *)in_buff + input->folder_offset);
    name.Length = input->folder_size;
    InitializeObjectAttributes( &attr, &name, 0, 0, NULL );

    for (;;)
    {
        if (!(buffer = HeapAlloc( GetProcessHeap(), 0, size )))
        {
            status = STATUS_NO_MEMORY;
            goto done;
        }
        status = wine_nt_to_unix_file_name( &attr, buffer, &size, FILE_OPEN_IF );
        if (status == STATUS_NO_SUCH_FILE) status = STATUS_SUCCESS;
        if (status == STATUS_SUCCESS) break;
        if (status != STATUS_BUFFER_TOO_SMALL) goto done;
        HeapFree( GetProcessHeap(), 0, buffer );
    }

    if (input->create_backup)
    {
        if (!(backup = HeapAlloc( GetProcessHeap(), 0, strlen(buffer) + sizeof(".backup" ) )))
        {
            status = STATUS_NO_MEMORY;
            goto done;
        }
        strcpy( backup, buffer );
        strcat( backup, ".backup" );
    }

    status = set_shell_folder( buffer, backup, link );

done:
    HeapFree( GetProcessHeap(), 0, buffer );
    HeapFree( GetProcessHeap(), 0, backup );
    return status;
}

/* implementation of IOCTL_MOUNTMGR_QUERY_SHELL_FOLDER */
static NTSTATUS query_shell_folder( void *buff, SIZE_T insize, SIZE_T outsize, IO_STATUS_BLOCK *iosb )
{
    char *output = buff;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    NTSTATUS status;
    ULONG size = 256;
    char *buffer;

    name.Buffer = buff;
    name.Length = insize;
    InitializeObjectAttributes( &attr, &name, 0, 0, NULL );

    for (;;)
    {
        if (!(buffer = HeapAlloc( GetProcessHeap(), 0, size ))) return STATUS_NO_MEMORY;
        status = wine_nt_to_unix_file_name( &attr, buffer, &size, FILE_OPEN );
        if (!status) break;
        HeapFree( GetProcessHeap(), 0, buffer );
        if (status != STATUS_BUFFER_TOO_SMALL) return status;
    }

    status = get_shell_folder( buffer, output, outsize );
    if (!status) iosb->Information = strlen(output) + 1;

    HeapFree( GetProcessHeap(), 0, buffer );
    return status;
}

/* implementation of IOCTL_MOUNTMGR_QUERY_DHCP_REQUEST_PARAMS */
static void WINAPI query_dhcp_request_params( TP_CALLBACK_INSTANCE *instance, void *context )
{
    IRP *irp = context;
    struct mountmgr_dhcp_request_params *query = irp->AssociatedIrp.SystemBuffer;
    IO_STACK_LOCATION *irpsp = IoGetCurrentIrpStackLocation( irp );
    SIZE_T insize = irpsp->Parameters.DeviceIoControl.InputBufferLength;
    SIZE_T outsize = irpsp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG i, offset = 0;

    /* sanity checks */
    if (FIELD_OFFSET(struct mountmgr_dhcp_request_params, params[query->count]) > insize)
    {
        irp->IoStatus.u.Status = STATUS_INVALID_PARAMETER;
        goto err;
    }

    for (i = 0; i < query->count; i++)
        if (query->params[i].offset + query->params[i].size > insize)
        {
            irp->IoStatus.u.Status = STATUS_INVALID_PARAMETER;
            goto err;
        }

    if (!memchr( query->unix_name, 0, sizeof(query->unix_name) ))
    {
        irp->IoStatus.u.Status = STATUS_INVALID_PARAMETER;
        goto err;
    }

    offset = FIELD_OFFSET(struct mountmgr_dhcp_request_params, params[query->count]);
    for (i = 0; i < query->count; i++)
    {
        offset += get_dhcp_request_param( query->unix_name, &query->params[i], (char *)query, offset, outsize - offset );
        if (offset > outsize)
        {
            if (offset >= sizeof(query->size)) query->size = offset;
            offset = sizeof(query->size);
            irp->IoStatus.u.Status = STATUS_BUFFER_OVERFLOW;
            goto err;
        }
    }
    irp->IoStatus.u.Status = STATUS_SUCCESS;

err:
    irp->IoStatus.Information = offset;
    IoCompleteRequest( irp, IO_NO_INCREMENT );
}

static void WINAPI query_symbol_file_callback( TP_CALLBACK_INSTANCE *instance, void *context )
{
    IRP *irp = context;
    IO_STACK_LOCATION *irpsp = IoGetCurrentIrpStackLocation( irp );
    ULONG info = 0;
    NTSTATUS status = query_symbol_file( irp->AssociatedIrp.SystemBuffer,
                                         irpsp->Parameters.DeviceIoControl.InputBufferLength,
                                         irpsp->Parameters.DeviceIoControl.OutputBufferLength,
                                         &info );
    irp->IoStatus.Information = info;
    irp->IoStatus.u.Status = status;
    IoCompleteRequest( irp, IO_NO_INCREMENT );
}

/* handler for ioctls on the mount manager device */
static NTSTATUS WINAPI mountmgr_ioctl( DEVICE_OBJECT *device, IRP *irp )
{
    IO_STACK_LOCATION *irpsp = IoGetCurrentIrpStackLocation( irp );
    NTSTATUS status;
    ULONG info = 0;

    TRACE( "ioctl %x insize %u outsize %u\n",
           irpsp->Parameters.DeviceIoControl.IoControlCode,
           irpsp->Parameters.DeviceIoControl.InputBufferLength,
           irpsp->Parameters.DeviceIoControl.OutputBufferLength );

    switch(irpsp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_MOUNTMGR_QUERY_POINTS:
        status = query_mount_points( irp->AssociatedIrp.SystemBuffer,
                                     irpsp->Parameters.DeviceIoControl.InputBufferLength,
                                     irpsp->Parameters.DeviceIoControl.OutputBufferLength,
                                     &irp->IoStatus );
        break;
    case IOCTL_MOUNTMGR_DEFINE_UNIX_DRIVE:
        if (irpsp->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct mountmgr_unix_drive))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        irp->IoStatus.Information = 0;
        status = define_unix_drive( irp->AssociatedIrp.SystemBuffer,
                                    irpsp->Parameters.DeviceIoControl.InputBufferLength );
        break;
    case IOCTL_MOUNTMGR_QUERY_UNIX_DRIVE:
        if (irpsp->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct mountmgr_unix_drive))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = query_unix_drive( irp->AssociatedIrp.SystemBuffer,
                                   irpsp->Parameters.DeviceIoControl.InputBufferLength,
                                   irpsp->Parameters.DeviceIoControl.OutputBufferLength,
                                   &irp->IoStatus );
        break;
    case IOCTL_MOUNTMGR_DEFINE_SHELL_FOLDER:
        if (irpsp->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct mountmgr_shell_folder))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        irp->IoStatus.Information = 0;
        status = define_shell_folder( irp->AssociatedIrp.SystemBuffer,
                                      irpsp->Parameters.DeviceIoControl.InputBufferLength );
        break;
    case IOCTL_MOUNTMGR_QUERY_SHELL_FOLDER:
        if (irpsp->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct mountmgr_shell_folder))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = query_shell_folder( irp->AssociatedIrp.SystemBuffer,
                                     irpsp->Parameters.DeviceIoControl.InputBufferLength,
                                     irpsp->Parameters.DeviceIoControl.OutputBufferLength,
                                     &irp->IoStatus );
        break;
    case IOCTL_MOUNTMGR_QUERY_DHCP_REQUEST_PARAMS:
        if (irpsp->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct mountmgr_dhcp_request_params))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (TrySubmitThreadpoolCallback( query_dhcp_request_params, irp, NULL ))
            return (irp->IoStatus.u.Status = STATUS_PENDING);
        status = STATUS_NO_MEMORY;
        break;
    case IOCTL_MOUNTMGR_QUERY_SYMBOL_FILE:
        if (irpsp->Parameters.DeviceIoControl.InputBufferLength != sizeof(GUID)
            || irpsp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MOUNTMGR_TARGET_NAME))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (TrySubmitThreadpoolCallback( query_symbol_file_callback, irp, NULL ))
            return (irp->IoStatus.u.Status = STATUS_PENDING);
        status = STATUS_NO_MEMORY;
        break;
    case IOCTL_MOUNTMGR_READ_CREDENTIAL:
        if (irpsp->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct mountmgr_credential))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = read_credential( irp->AssociatedIrp.SystemBuffer,
                                  irpsp->Parameters.DeviceIoControl.InputBufferLength,
                                  irpsp->Parameters.DeviceIoControl.OutputBufferLength,
                                  &info );
        irp->IoStatus.Information = info;
        break;
    case IOCTL_MOUNTMGR_WRITE_CREDENTIAL:
        if (irpsp->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct mountmgr_credential))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = write_credential( irp->AssociatedIrp.SystemBuffer,
                                   irpsp->Parameters.DeviceIoControl.InputBufferLength,
                                   irpsp->Parameters.DeviceIoControl.OutputBufferLength,
                                   &info );
        irp->IoStatus.Information = info;
        break;
    case IOCTL_MOUNTMGR_DELETE_CREDENTIAL:
        if (irpsp->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct mountmgr_credential))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = delete_credential( irp->AssociatedIrp.SystemBuffer,
                                    irpsp->Parameters.DeviceIoControl.InputBufferLength,
                                    irpsp->Parameters.DeviceIoControl.OutputBufferLength,
                                    &info );
        irp->IoStatus.Information = info;
        break;
    case IOCTL_MOUNTMGR_ENUMERATE_CREDENTIALS:
        if (irpsp->Parameters.DeviceIoControl.InputBufferLength < sizeof(struct mountmgr_credential_list))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = enumerate_credentials( irp->AssociatedIrp.SystemBuffer,
                                        irpsp->Parameters.DeviceIoControl.InputBufferLength,
                                        irpsp->Parameters.DeviceIoControl.OutputBufferLength,
                                        &info );
        irp->IoStatus.Information = info;
        break;
    default:
        FIXME( "ioctl %x not supported\n", irpsp->Parameters.DeviceIoControl.IoControlCode );
        status = STATUS_NOT_SUPPORTED;
        break;
    }
    irp->IoStatus.u.Status = status;
    IoCompleteRequest( irp, IO_NO_INCREMENT );
    return status;
}

/* main entry point for the mount point manager driver */
NTSTATUS WINAPI DriverEntry( DRIVER_OBJECT *driver, UNICODE_STRING *path )
{
    static const WCHAR mounted_devicesW[] = {'S','y','s','t','e','m','\\','M','o','u','n','t','e','d','D','e','v','i','c','e','s',0};
    static const WCHAR device_mountmgrW[] = {'\\','D','e','v','i','c','e','\\','M','o','u','n','t','P','o','i','n','t','M','a','n','a','g','e','r',0};
    static const WCHAR link_mountmgrW[] = {'\\','?','?','\\','M','o','u','n','t','P','o','i','n','t','M','a','n','a','g','e','r',0};
    static const WCHAR harddiskW[] = {'\\','D','r','i','v','e','r','\\','H','a','r','d','d','i','s','k',0};
    static const WCHAR driver_serialW[] = {'\\','D','r','i','v','e','r','\\','S','e','r','i','a','l',0};
    static const WCHAR driver_parallelW[] = {'\\','D','r','i','v','e','r','\\','P','a','r','a','l','l','e','l',0};
    static const WCHAR devicemapW[] = {'H','A','R','D','W','A','R','E','\\','D','E','V','I','C','E','M','A','P','\\','S','c','s','i',0};

#ifdef _WIN64
    static const WCHAR qualified_ports_keyW[] = {'\\','R','E','G','I','S','T','R','Y','\\',
                                                 'M','A','C','H','I','N','E','\\','S','o','f','t','w','a','r','e','\\',
                                                 'W','i','n','e','\\','P','o','r','t','s'}; /* no null terminator */
    static const WCHAR wow64_ports_keyW[] = {'S','o','f','t','w','a','r','e','\\',
                                             'W','o','w','6','4','3','2','N','o','d','e','\\','W','i','n','e','\\',
                                             'P','o','r','t','s',0};
    static const WCHAR symbolic_link_valueW[] = {'S','y','m','b','o','l','i','c','L','i','n','k','V','a','l','u','e',0};
    HKEY wow64_ports_key = NULL;
#endif

    UNICODE_STRING nameW, linkW;
    DEVICE_OBJECT *device;
    HKEY devicemap_key;
    NTSTATUS status;

    TRACE( "%s\n", debugstr_w(path->Buffer) );

    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = mountmgr_ioctl;

    RtlInitUnicodeString( &nameW, device_mountmgrW );
    RtlInitUnicodeString( &linkW, link_mountmgrW );
    if (!(status = IoCreateDevice( driver, 0, &nameW, 0, 0, FALSE, &device )))
        status = IoCreateSymbolicLink( &linkW, &nameW );
    if (status)
    {
        FIXME( "failed to create device error %x\n", status );
        return status;
    }

    RegCreateKeyExW( HKEY_LOCAL_MACHINE, mounted_devicesW, 0, NULL,
                     REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &mount_key, NULL );

    if (!RegCreateKeyExW( HKEY_LOCAL_MACHINE, devicemapW, 0, NULL, REG_OPTION_VOLATILE,
                          KEY_ALL_ACCESS, NULL, &devicemap_key, NULL ))
        RegCloseKey( devicemap_key );

    RtlInitUnicodeString( &nameW, harddiskW );
    status = IoCreateDriver( &nameW, harddisk_driver_entry );

    initialize_dbus();
    initialize_diskarbitration();

#ifdef _WIN64
    /* create a symlink so that the Wine port overrides key can be edited with 32-bit reg or regedit */
    RegCreateKeyExW( HKEY_LOCAL_MACHINE, wow64_ports_keyW, 0, NULL, REG_OPTION_CREATE_LINK,
                     KEY_SET_VALUE, NULL, &wow64_ports_key, NULL );
    RegSetValueExW( wow64_ports_key, symbolic_link_valueW, 0, REG_LINK,
                    (BYTE *)qualified_ports_keyW, sizeof(qualified_ports_keyW) );
    RegCloseKey( wow64_ports_key );
#endif

    RtlInitUnicodeString( &nameW, driver_serialW );
    IoCreateDriver( &nameW, serial_driver_entry );

    RtlInitUnicodeString( &nameW, driver_parallelW );
    IoCreateDriver( &nameW, parallel_driver_entry );

    return status;
}
