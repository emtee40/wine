/*
 * crypt32 cert functions tests
 *
 * Copyright 2005-2006 Juan Lang
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
#include <stdarg.h>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winerror.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include "wine/test.h"

static PCCERT_CONTEXT (WINAPI *pCertCreateSelfSignCertificate)(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,PCERT_NAME_BLOB,DWORD,PCRYPT_KEY_PROV_INFO,PCRYPT_ALGORITHM_IDENTIFIER,PSYSTEMTIME,PSYSTEMTIME,PCERT_EXTENSIONS);
static BOOL (WINAPI *pCertGetValidUsages)(DWORD,PCCERT_CONTEXT*,int*,LPSTR*,DWORD*);
static BOOL (WINAPI *pCryptAcquireCertificatePrivateKey)(PCCERT_CONTEXT,DWORD,void*,HCRYPTPROV_OR_NCRYPT_KEY_HANDLE*,DWORD*,BOOL*);
static BOOL (WINAPI *pCryptEncodeObjectEx)(DWORD,LPCSTR,const void*,DWORD,PCRYPT_ENCODE_PARA,void*,DWORD*);
static BOOL (WINAPI *pCryptHashCertificate2)(LPCWSTR, DWORD, void*, const BYTE*, DWORD, BYTE*, DWORD*);
static BOOL (WINAPI * pCryptVerifyCertificateSignatureEx)
                        (HCRYPTPROV, DWORD, DWORD, void *, DWORD, void *, DWORD, void *);

static BOOL (WINAPI * pCryptAcquireContextA)
                        (HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD);

static void init_function_pointers(void)
{
    HMODULE hCrypt32 = GetModuleHandleA("crypt32.dll");
    HMODULE hAdvapi32 = GetModuleHandleA("advapi32.dll");

#define GET_PROC(dll, func) \
    p ## func = (void *)GetProcAddress(dll, #func); \
    if(!p ## func) \
      trace("GetProcAddress(%s) failed\n", #func);

    GET_PROC(hCrypt32, CertCreateSelfSignCertificate)
    GET_PROC(hCrypt32, CertGetValidUsages)
    GET_PROC(hCrypt32, CryptAcquireCertificatePrivateKey)
    GET_PROC(hCrypt32, CryptEncodeObjectEx)
    GET_PROC(hCrypt32, CryptHashCertificate2)
    GET_PROC(hCrypt32, CryptVerifyCertificateSignatureEx)

    GET_PROC(hAdvapi32, CryptAcquireContextA)
#undef GET_PROC
}

static BYTE subjectName[] = { 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06,
 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x4a, 0x75, 0x61, 0x6e, 0x20, 0x4c, 0x61,
 0x6e, 0x67, 0x00 };
static BYTE serialNum[] = { 1 };
static const BYTE bigCert[] = { 0x30, 0x7a, 0x02, 0x01, 0x01, 0x30, 0x02, 0x06,
 0x00, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
 0x0a, 0x4a, 0x75, 0x61, 0x6e, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x00, 0x30, 0x22,
 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30,
 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x15, 0x31, 0x13, 0x30,
 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x4a, 0x75, 0x61, 0x6e, 0x20,
 0x4c, 0x61, 0x6e, 0x67, 0x00, 0x30, 0x07, 0x30, 0x02, 0x06, 0x00, 0x03, 0x01,
 0x00, 0xa3, 0x16, 0x30, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01 };
static BYTE bigCertHash[] = { 0x6e, 0x30, 0x90, 0x71, 0x5f, 0xd9, 0x23,
 0x56, 0xeb, 0xae, 0x25, 0x40, 0xe6, 0x22, 0xda, 0x19, 0x26, 0x02, 0xa6, 0x08 };

static const BYTE bigCertWithDifferentSubject[] = { 0x30, 0x7a, 0x02, 0x01, 0x02,
 0x30, 0x02, 0x06, 0x00, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
 0x04, 0x03, 0x13, 0x0a, 0x4a, 0x75, 0x61, 0x6e, 0x20, 0x4c, 0x61, 0x6e, 0x67,
 0x00, 0x30, 0x22, 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31,
 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31,
 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x15,
 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x41, 0x6c,
 0x65, 0x78, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x00, 0x30, 0x07, 0x30, 0x02, 0x06,
 0x00, 0x03, 0x01, 0x00, 0xa3, 0x16, 0x30, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55,
 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02,
 0x01, 0x01 };
static const BYTE bigCertWithDifferentIssuer[] = { 0x30, 0x7a, 0x02, 0x01,
 0x01, 0x30, 0x02, 0x06, 0x00, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
 0x55, 0x04, 0x03, 0x13, 0x0a, 0x41, 0x6c, 0x65, 0x78, 0x20, 0x4c, 0x61, 0x6e,
 0x67, 0x00, 0x30, 0x22, 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30,
 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x31, 0x36, 0x30,
 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30,
 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x4a,
 0x75, 0x61, 0x6e, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x00, 0x30, 0x07, 0x30, 0x02,
 0x06, 0x00, 0x03, 0x01, 0x00, 0xa3, 0x16, 0x30, 0x14, 0x30, 0x12, 0x06, 0x03,
 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff,
 0x02, 0x01, 0x01 };

static BYTE subjectName2[] = { 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06,
 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x41, 0x6c, 0x65, 0x78, 0x20, 0x4c, 0x61,
 0x6e, 0x67, 0x00 };
static const BYTE bigCert2[] = { 0x30, 0x7a, 0x02, 0x01, 0x01, 0x30, 0x02, 0x06,
 0x00, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
 0x0a, 0x41, 0x6c, 0x65, 0x78, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x00, 0x30, 0x22,
 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30,
 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x15, 0x31, 0x13, 0x30,
 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x41, 0x6c, 0x65, 0x78, 0x20,
 0x4c, 0x61, 0x6e, 0x67, 0x00, 0x30, 0x07, 0x30, 0x02, 0x06, 0x00, 0x03, 0x01,
 0x00, 0xa3, 0x16, 0x30, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01 };
static const BYTE bigCert2WithDifferentSerial[] = { 0x30, 0x7a, 0x02, 0x01,
 0x02, 0x30, 0x02, 0x06, 0x00, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
 0x55, 0x04, 0x03, 0x13, 0x0a, 0x41, 0x6c, 0x65, 0x78, 0x20, 0x4c, 0x61, 0x6e,
 0x67, 0x00, 0x30, 0x22, 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30,
 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x31, 0x36, 0x30,
 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30,
 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x41,
 0x6c, 0x65, 0x78, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x00, 0x30, 0x07, 0x30, 0x02,
 0x06, 0x00, 0x03, 0x01, 0x00, 0xa3, 0x16, 0x30, 0x14, 0x30, 0x12, 0x06, 0x03,
 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff,
 0x02, 0x01, 0x01 };
static BYTE bigCert2Hash[] = { 0x4a, 0x7f, 0x32, 0x1f, 0xcf, 0x3b, 0xc0,
 0x87, 0x48, 0x2b, 0xa1, 0x86, 0x54, 0x18, 0xe4, 0x3a, 0x0e, 0x53, 0x7e, 0x2b };

static const BYTE certWithUsage[] = { 0x30, 0x81, 0x93, 0x02, 0x01, 0x01, 0x30,
 0x02, 0x06, 0x00, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
 0x03, 0x13, 0x0a, 0x4a, 0x75, 0x61, 0x6e, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x00,
 0x30, 0x22, 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30,
 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31, 0x30,
 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x15, 0x31,
 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x4a, 0x75, 0x61,
 0x6e, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x00, 0x30, 0x07, 0x30, 0x02, 0x06, 0x00,
 0x03, 0x01, 0x00, 0xa3, 0x2f, 0x30, 0x2d, 0x30, 0x2b, 0x06, 0x03, 0x55, 0x1d,
 0x25, 0x01, 0x01, 0xff, 0x04, 0x21, 0x30, 0x1f, 0x06, 0x08, 0x2b, 0x06, 0x01,
 0x05, 0x05, 0x07, 0x03, 0x03, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
 0x03, 0x02, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

static void testAddCert(void)
{
    HCERTSTORE store;
    HCERTSTORE collection;
    PCCERT_CONTEXT context;
    PCCERT_CONTEXT copyContext;
    BOOL ret;

    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(store != NULL, "CertOpenStore failed: %d\n", GetLastError());
    if (!store)
        return;

    /* Weird--bad add disposition leads to an access violation in Windows.
     * Both tests crash on some win9x boxes.
     */
    if (0)
    {
        ret = CertAddEncodedCertificateToStore(0, X509_ASN_ENCODING, bigCert,
         sizeof(bigCert), 0, NULL);
        ok(!ret && (GetLastError() == STATUS_ACCESS_VIOLATION ||
         GetLastError() == E_INVALIDARG),
         "Expected STATUS_ACCESS_VIOLATION or E_INVALIDARG, got %08x\n",
         GetLastError());
        ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
         bigCert, sizeof(bigCert), 0, NULL);
        ok(!ret && (GetLastError() == STATUS_ACCESS_VIOLATION ||
         GetLastError() == E_INVALIDARG),
         "Expected STATUS_ACCESS_VIOLATION or E_INVALIDARG, got %08x\n",
         GetLastError());
    }

    /* Weird--can add a cert to the NULL store (does this have special
     * meaning?)
     */
    context = NULL;
    ret = CertAddEncodedCertificateToStore(0, X509_ASN_ENCODING, bigCert,
     sizeof(bigCert), CERT_STORE_ADD_ALWAYS, &context);
    ok(ret || broken(GetLastError() == OSS_DATA_ERROR /* win98 */),
     "CertAddEncodedCertificateToStore failed: %08x\n", GetLastError());
    if (context)
        CertFreeCertificateContext(context);
    if (!ret && GetLastError() == OSS_DATA_ERROR)
    {
        skip("bigCert can't be decoded, skipping tests\n");
        return;
    }

    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     bigCert, sizeof(bigCert), CERT_STORE_ADD_ALWAYS, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     bigCert2, sizeof(bigCert2), CERT_STORE_ADD_NEW, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());
    /* This has the same name as bigCert, so finding isn't done by name */
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     certWithUsage, sizeof(certWithUsage), CERT_STORE_ADD_NEW, &context);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());
    ok(context != NULL, "Expected a context\n");
    if (context)
    {
        CRYPT_DATA_BLOB hash = { sizeof(bigCert2Hash), bigCert2Hash };

        /* Duplicate (AddRef) the context so we can still use it after
         * deleting it from the store.
         */
        CertDuplicateCertificateContext(context);
        CertDeleteCertificateFromStore(context);
        /* Set the same hash as bigCert2, and try to readd it */
        ret = CertSetCertificateContextProperty(context, CERT_HASH_PROP_ID,
         0, &hash);
        ok(ret, "CertSetCertificateContextProperty failed: %08x\n",
         GetLastError());
        ret = CertAddCertificateContextToStore(store, context,
         CERT_STORE_ADD_NEW, NULL);
        /* The failure is a bit odd (CRYPT_E_ASN1_BADTAG), so just check
         * that it fails.
         */
        ok(!ret, "Expected failure\n");
        CertFreeCertificateContext(context);
    }
    context = CertCreateCertificateContext(X509_ASN_ENCODING, bigCert2,
     sizeof(bigCert2));
    ok(context != NULL, "Expected a context\n");
    if (context)
    {
        /* Try to readd bigCert2 to the store */
        ret = CertAddCertificateContextToStore(store, context,
         CERT_STORE_ADD_NEW, NULL);
        ok(!ret && GetLastError() == CRYPT_E_EXISTS,
         "Expected CRYPT_E_EXISTS, got %08x\n", GetLastError());
        CertFreeCertificateContext(context);
    }

    /* Adding a cert with the same issuer name and serial number (but
     * different subject) as an existing cert succeeds.
     */
    context = NULL;
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     bigCert2WithDifferentSerial, sizeof(bigCert2WithDifferentSerial),
     CERT_STORE_ADD_NEW, &context);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());
    if (context)
        CertDeleteCertificateFromStore(context);

    /* Adding a cert with the same subject name and serial number (but
     * different issuer) as an existing cert succeeds.
     */
    context = NULL;
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     bigCertWithDifferentSubject, sizeof(bigCertWithDifferentSubject),
     CERT_STORE_ADD_NEW, &context);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());
    if (context)
        CertDeleteCertificateFromStore(context);

    /* Adding a cert with the same issuer name and serial number (but
     * different otherwise) as an existing cert succeeds.
     */
    context = NULL;
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     bigCertWithDifferentIssuer, sizeof(bigCertWithDifferentIssuer),
     CERT_STORE_ADD_NEW, &context);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());
    if (context)
        CertDeleteCertificateFromStore(context);

    collection = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(collection != NULL, "CertOpenStore failed: %08x\n", GetLastError());
    if (collection)
    {
        /* Add store to the collection, but disable updates */
        CertAddStoreToCollection(collection, store, 0, 0);

        context = CertCreateCertificateContext(X509_ASN_ENCODING, bigCert2,
         sizeof(bigCert2));
        ok(context != NULL, "Expected a context\n");
        if (context)
        {
            /* Try to readd bigCert2 to the collection */
            ret = CertAddCertificateContextToStore(collection, context,
             CERT_STORE_ADD_NEW, NULL);
            ok(!ret && GetLastError() == CRYPT_E_EXISTS,
             "Expected CRYPT_E_EXISTS, got %08x\n", GetLastError());
            /* Replacing an existing certificate context is allowed, even
             * though updates to the collection aren't..
             */
            ret = CertAddCertificateContextToStore(collection, context,
             CERT_STORE_ADD_REPLACE_EXISTING, NULL);
            ok(ret, "CertAddCertificateContextToStore failed: %08x\n",
             GetLastError());
            /* use the existing certificate and ask for a copy of the context*/
            copyContext = NULL;
            ret = CertAddCertificateContextToStore(collection, context,
             CERT_STORE_ADD_USE_EXISTING, &copyContext);
            ok(ret, "CertAddCertificateContextToStore failed: %08x\n",
             GetLastError());
            ok(copyContext != NULL, "Expected on output a non NULL copyContext\n");
            if (copyContext)
                CertFreeCertificateContext(copyContext);
            /* but adding a new certificate isn't allowed. */
            ret = CertAddCertificateContextToStore(collection, context,
             CERT_STORE_ADD_ALWAYS, NULL);
            ok(!ret && GetLastError() == E_ACCESSDENIED,
             "Expected E_ACCESSDENIED, got %08x\n", GetLastError());
            CertFreeCertificateContext(context);
        }

        CertCloseStore(collection, 0);
    }

    CertCloseStore(store, 0);
}

static void checkHash(const BYTE *data, DWORD dataLen, ALG_ID algID,
 PCCERT_CONTEXT context, DWORD propID)
{
    BYTE hash[20] = { 0 }, hashProperty[20];
    BOOL ret;
    DWORD size;
    DWORD dwSizeWithNull;

    memset(hash, 0, sizeof(hash));
    memset(hashProperty, 0, sizeof(hashProperty));
    size = sizeof(hash);
    ret = CryptHashCertificate(0, algID, 0, data, dataLen, hash, &size);
    ok(ret, "CryptHashCertificate failed: %08x\n", GetLastError());
    ret = CertGetCertificateContextProperty(context, propID, NULL,
     &dwSizeWithNull);
    ok(ret, "algID %08x, propID %d: CertGetCertificateContextProperty failed: %08x\n",
     algID, propID, GetLastError());
    ret = CertGetCertificateContextProperty(context, propID, hashProperty,
     &size);
    ok(ret, "CertGetCertificateContextProperty failed: %08x\n",
     GetLastError());
    ok(!memcmp(hash, hashProperty, size), "Unexpected hash for property %d\n",
     propID);
    ok(size == dwSizeWithNull, "Unexpected length of hash for property: received %d instead of %d\n",
     dwSizeWithNull,size);
}

static const CHAR cspNameA[] = "WineCryptTemp";
static WCHAR cspNameW[] = { 'W','i','n','e','C','r','y','p','t','T','e','m','p',0 };
static const BYTE v1CertWithPubKey[] = {
0x30,0x81,0x95,0x02,0x01,0x01,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,
0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,
0x6e,0x67,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,
0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,
0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x15,0x31,0x13,0x30,0x11,
0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,
0x67,0x00,0x30,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
0x01,0x01,0x05,0x00,0x03,0x11,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xa3,0x16,0x30,0x14,0x30,0x12,0x06,
0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,0x01,0x01,0xff,0x02,
0x01,0x01 };
static const BYTE v1CertWithSubjectKeyId[] = {
0x30,0x7b,0x02,0x01,0x01,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,0x11,
0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,
0x67,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,
0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,
0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x15,0x31,0x13,0x30,0x11,0x06,
0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,
0x00,0x30,0x07,0x30,0x02,0x06,0x00,0x03,0x01,0x00,0xa3,0x17,0x30,0x15,0x30,
0x13,0x06,0x03,0x55,0x1d,0x0e,0x04,0x0c,0x04,0x0a,0x4a,0x75,0x61,0x6e,0x20,
0x4c,0x61,0x6e,0x67,0x00 };
static const BYTE subjectKeyId[] = {
0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00 };
static const BYTE selfSignedCert[] = {
 0x30, 0x82, 0x01, 0x1f, 0x30, 0x81, 0xce, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
 0x10, 0xeb, 0x0d, 0x57, 0x2a, 0x9c, 0x09, 0xba, 0xa4, 0x4a, 0xb7, 0x25, 0x49,
 0xd9, 0x3e, 0xb5, 0x73, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1d,
 0x05, 0x00, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03,
 0x13, 0x0a, 0x4a, 0x75, 0x61, 0x6e, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x00, 0x30,
 0x1e, 0x17, 0x0d, 0x30, 0x36, 0x30, 0x36, 0x32, 0x39, 0x30, 0x35, 0x30, 0x30,
 0x34, 0x36, 0x5a, 0x17, 0x0d, 0x30, 0x37, 0x30, 0x36, 0x32, 0x39, 0x31, 0x31,
 0x30, 0x30, 0x34, 0x36, 0x5a, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
 0x55, 0x04, 0x03, 0x13, 0x0a, 0x4a, 0x75, 0x61, 0x6e, 0x20, 0x4c, 0x61, 0x6e,
 0x67, 0x00, 0x30, 0x5c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x4b, 0x00, 0x30, 0x48, 0x02, 0x41,
 0x00, 0xe2, 0x54, 0x3a, 0xa7, 0x83, 0xb1, 0x27, 0x14, 0x3e, 0x59, 0xbb, 0xb4,
 0x53, 0xe6, 0x1f, 0xe7, 0x5d, 0xf1, 0x21, 0x68, 0xad, 0x85, 0x53, 0xdb, 0x6b,
 0x1e, 0xeb, 0x65, 0x97, 0x03, 0x86, 0x60, 0xde, 0xf3, 0x6c, 0x38, 0x75, 0xe0,
 0x4c, 0x61, 0xbb, 0xbc, 0x62, 0x17, 0xa9, 0xcd, 0x79, 0x3f, 0x21, 0x4e, 0x96,
 0xcb, 0x0e, 0xdc, 0x61, 0x94, 0x30, 0x18, 0x10, 0x6b, 0xd0, 0x1c, 0x10, 0x79,
 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
 0x1d, 0x05, 0x00, 0x03, 0x41, 0x00, 0x25, 0x90, 0x53, 0x34, 0xd9, 0x56, 0x41,
 0x5e, 0xdb, 0x7e, 0x01, 0x36, 0xec, 0x27, 0x61, 0x5e, 0xb7, 0x4d, 0x90, 0x66,
 0xa2, 0xe1, 0x9d, 0x58, 0x76, 0xd4, 0x9c, 0xba, 0x2c, 0x84, 0xc6, 0x83, 0x7a,
 0x22, 0x0d, 0x03, 0x69, 0x32, 0x1a, 0x6d, 0xcb, 0x0c, 0x15, 0xb3, 0x6b, 0xc7,
 0x0a, 0x8c, 0xb4, 0x5c, 0x34, 0x78, 0xe0, 0x3c, 0x9c, 0xe9, 0xf3, 0x30, 0x9f,
 0xa8, 0x76, 0x57, 0x92, 0x36 };
static const BYTE selfSignedSignatureHash[] = { 0x07,0x5a,0x3e,0xfd,0x0d,0xf6,
 0x88,0xeb,0x00,0x64,0xbd,0xc9,0xd6,0xea,0x0a,0x7c,0xcc,0x24,0xdb,0x5d };

static void testCertProperties(void)
{
    PCCERT_CONTEXT context = CertCreateCertificateContext(X509_ASN_ENCODING,
     bigCert, sizeof(bigCert));
    DWORD propID, numProps, access, size;
    BOOL ret;
    BYTE hash[20] = { 0 }, hashProperty[20];
    CRYPT_DATA_BLOB blob;
    CERT_KEY_CONTEXT keyContext;

    ok(context != NULL || broken(GetLastError() == OSS_DATA_ERROR /* win98 */),
     "CertCreateCertificateContext failed: %08x\n", GetLastError());
    if (!context)
        return;

    /* This crashes
    propID = CertEnumCertificateContextProperties(NULL, 0);
     */

    propID = 0;
    numProps = 0;
    do {
        propID = CertEnumCertificateContextProperties(context, propID);
        if (propID)
            numProps++;
    } while (propID != 0);
    ok(numProps == 0, "Expected 0 properties, got %d\n", numProps);

    /* Tests with a NULL cert context.  Prop ID 0 fails.. */
    ret = CertSetCertificateContextProperty(NULL, 0, 0, NULL);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());
    /* while this just crashes.
    ret = CertSetCertificateContextProperty(NULL,
     CERT_KEY_PROV_HANDLE_PROP_ID, 0, NULL);
     */

    ret = CertSetCertificateContextProperty(context, 0, 0, NULL);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());
    /* Can't set the cert property directly, this crashes.
    ret = CertSetCertificateContextProperty(context,
     CERT_CERT_PROP_ID, 0, bigCert2);
     */

    /* These all crash.
    ret = CertGetCertificateContextProperty(context,
     CERT_ACCESS_STATE_PROP_ID, 0, NULL);
    ret = CertGetCertificateContextProperty(context, CERT_HASH_PROP_ID, 
     NULL, NULL);
    ret = CertGetCertificateContextProperty(context, CERT_HASH_PROP_ID, 
     hashProperty, NULL);
     */
    /* A missing prop */
    size = 0;
    ret = CertGetCertificateContextProperty(context,
     CERT_KEY_PROV_INFO_PROP_ID, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_NOT_FOUND,
     "Expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());
    /* And, an implicit property */
    size = sizeof(access);
    ret = CertGetCertificateContextProperty(context,
     CERT_ACCESS_STATE_PROP_ID, &access, &size);
    ok(ret, "CertGetCertificateContextProperty failed: %08x\n",
     GetLastError());
    ok(!(access & CERT_ACCESS_STATE_WRITE_PERSIST_FLAG),
     "Didn't expect a persisted cert\n");
    /* Trying to set this "read only" property crashes.
    access |= CERT_ACCESS_STATE_WRITE_PERSIST_FLAG;
    ret = CertSetCertificateContextProperty(context,
     CERT_ACCESS_STATE_PROP_ID, 0, &access);
     */

    /* Can I set the hash to an invalid hash? */
    blob.pbData = hash;
    blob.cbData = sizeof(hash);
    ret = CertSetCertificateContextProperty(context, CERT_HASH_PROP_ID, 0,
     &blob);
    ok(ret, "CertSetCertificateContextProperty failed: %08x\n",
     GetLastError());
    size = sizeof(hashProperty);
    ret = CertGetCertificateContextProperty(context, CERT_HASH_PROP_ID,
     hashProperty, &size);
    ok(ret, "CertGetCertificateContextProperty failed: %08x\n",
     GetLastError());
    ok(!memcmp(hashProperty, hash, sizeof(hash)), "Unexpected hash\n");
    /* Delete the (bogus) hash, and get the real one */
    ret = CertSetCertificateContextProperty(context, CERT_HASH_PROP_ID, 0,
     NULL);
    ok(ret, "CertSetCertificateContextProperty failed: %08x\n",
     GetLastError());
    checkHash(bigCert, sizeof(bigCert), CALG_SHA1, context,
     CERT_HASH_PROP_ID);

    /* Now that the hash property is set, we should get one property when
     * enumerating.
     */
    propID = 0;
    numProps = 0;
    do {
        propID = CertEnumCertificateContextProperties(context, propID);
        if (propID)
            numProps++;
    } while (propID != 0);
    ok(numProps == 1, "Expected 1 properties, got %d\n", numProps);

    /* Check a few other implicit properties */
    checkHash(bigCert, sizeof(bigCert), CALG_MD5, context,
     CERT_MD5_HASH_PROP_ID);

    /* Getting the signature hash fails with this bogus certificate */
    size = 0;
    ret = CertGetCertificateContextProperty(context,
     CERT_SIGNATURE_HASH_PROP_ID, NULL, &size);
    ok(!ret &&
       (GetLastError() == CRYPT_E_ASN1_BADTAG ||
        GetLastError() == CRYPT_E_NOT_FOUND ||
        GetLastError() == OSS_DATA_ERROR), /* win9x */
       "Expected CRYPT_E_ASN1_BADTAG, got %08x\n", GetLastError());

    /* Test key contexts and handles and such */
    size = 0;
    ret = CertGetCertificateContextProperty(context, CERT_KEY_CONTEXT_PROP_ID,
     NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_NOT_FOUND,
     "Expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());
    size = sizeof(CERT_KEY_CONTEXT);
    ret = CertGetCertificateContextProperty(context, CERT_KEY_CONTEXT_PROP_ID,
     NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_NOT_FOUND,
     "Expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());
    ret = CertGetCertificateContextProperty(context, CERT_KEY_CONTEXT_PROP_ID,
     &keyContext, &size);
    ok(!ret && GetLastError() == CRYPT_E_NOT_FOUND,
     "Expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());
    /* Key context with an invalid size */
    keyContext.cbSize = 0;
    ret = CertSetCertificateContextProperty(context, CERT_KEY_CONTEXT_PROP_ID,
     0, &keyContext);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());
    size = sizeof(keyContext);
    ret = CertGetCertificateContextProperty(context, CERT_KEY_CONTEXT_PROP_ID,
     &keyContext, &size);
    ok(!ret && GetLastError() == CRYPT_E_NOT_FOUND,
     "Expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());
    keyContext.cbSize = sizeof(keyContext);
    keyContext.hCryptProv = 0;
    keyContext.dwKeySpec = AT_SIGNATURE;
    ret = CertSetCertificateContextProperty(context, CERT_KEY_CONTEXT_PROP_ID,
     0, &keyContext);
    ok(ret, "CertSetCertificateContextProperty failed: %08x\n", GetLastError());
    /* Now that that's set, the key prov handle property is also gettable.
     */
    size = sizeof(keyContext.hCryptProv);
    ret = CertGetCertificateContextProperty(context,
     CERT_KEY_PROV_HANDLE_PROP_ID, &keyContext.hCryptProv, &size);
    ok(ret, "Expected to get the CERT_KEY_PROV_HANDLE_PROP_ID, got %08x\n",
     GetLastError());
    /* Remove the key prov handle property.. */
    ret = CertSetCertificateContextProperty(context,
     CERT_KEY_PROV_HANDLE_PROP_ID, 0, NULL);
    ok(ret, "CertSetCertificateContextProperty failed: %08x\n",
     GetLastError());
    /* and the key context's CSP is set to NULL. */
    size = sizeof(keyContext);
    ret = CertGetCertificateContextProperty(context,
     CERT_KEY_CONTEXT_PROP_ID, &keyContext, &size);
    ok(ret, "CertGetCertificateContextProperty failed: %08x\n",
     GetLastError());
    ok(keyContext.hCryptProv == 0, "Expected no hCryptProv\n");

    /* According to MSDN the subject key id can be stored as a property,
     * as a subject key extension, or as the SHA1 hash of the public key,
     * but this cert has none of them:
     */
    ret = CertGetCertificateContextProperty(context,
     CERT_KEY_IDENTIFIER_PROP_ID, NULL, &size);
    ok(!ret && GetLastError() == ERROR_INVALID_DATA,
     "Expected ERROR_INVALID_DATA, got %08x\n", GetLastError());
    CertFreeCertificateContext(context);
    /* This cert does have a public key, but its subject key identifier still
     * isn't available: */
    context = CertCreateCertificateContext(X509_ASN_ENCODING,
     v1CertWithPubKey, sizeof(v1CertWithPubKey));
    ret = CertGetCertificateContextProperty(context,
     CERT_KEY_IDENTIFIER_PROP_ID, NULL, &size);
    ok(!ret && GetLastError() == ERROR_INVALID_DATA,
     "Expected ERROR_INVALID_DATA, got %08x\n", GetLastError());
    CertFreeCertificateContext(context);
    /* This cert with a subject key extension can have its key identifier
     * property retrieved:
     */
    context = CertCreateCertificateContext(X509_ASN_ENCODING,
     v1CertWithSubjectKeyId, sizeof(v1CertWithSubjectKeyId));
    ret = CertGetCertificateContextProperty(context,
     CERT_KEY_IDENTIFIER_PROP_ID, NULL, &size);
    ok(ret, "CertGetCertificateContextProperty failed: %08x\n", GetLastError());
    if (ret)
    {
        LPBYTE buf = HeapAlloc(GetProcessHeap(), 0, size);

        if (buf)
        {
            ret = CertGetCertificateContextProperty(context,
             CERT_KEY_IDENTIFIER_PROP_ID, buf, &size);
            ok(ret, "CertGetCertificateContextProperty failed: %08x\n",
             GetLastError());
            ok(!memcmp(buf, subjectKeyId, size), "Unexpected subject key id\n");
            HeapFree(GetProcessHeap(), 0, buf);
        }
    }
    CertFreeCertificateContext(context);

    context = CertCreateCertificateContext(X509_ASN_ENCODING,
     selfSignedCert, sizeof(selfSignedCert));
    /* Getting the signature hash of a valid (self-signed) cert succeeds */
    size = 0;
    ret = CertGetCertificateContextProperty(context,
     CERT_SIGNATURE_HASH_PROP_ID, NULL, &size);
    ok(ret, "CertGetCertificateContextProperty failed: %08x\n", GetLastError());
    ok(size == sizeof(selfSignedSignatureHash), "unexpected size %d\n", size);
    ret = CertGetCertificateContextProperty(context,
     CERT_SIGNATURE_HASH_PROP_ID, hashProperty, &size);
    if (ret)
        ok(!memcmp(hashProperty, selfSignedSignatureHash, size),
         "unexpected value\n");
    CertFreeCertificateContext(context);
}

static void testCreateCert(void)
{
    PCCERT_CONTEXT cert, enumCert;
    DWORD count, size;
    BOOL ret;

    SetLastError(0xdeadbeef);
    cert = CertCreateCertificateContext(0, NULL, 0);
    ok(!cert && GetLastError() == E_INVALIDARG,
     "expected E_INVALIDARG, got %08x\n", GetLastError());
    SetLastError(0xdeadbeef);
    cert = CertCreateCertificateContext(0, selfSignedCert,
     sizeof(selfSignedCert));
    ok(!cert && GetLastError() == E_INVALIDARG,
     "expected E_INVALIDARG, got %08x\n", GetLastError());
    SetLastError(0xdeadbeef);
    cert = CertCreateCertificateContext(X509_ASN_ENCODING, NULL, 0);
    ok(!cert &&
     (GetLastError() == CRYPT_E_ASN1_EOD ||
     broken(GetLastError() == OSS_MORE_INPUT /* NT4 */)),
     "expected CRYPT_E_ASN1_EOD, got %08x\n", GetLastError());

    cert = CertCreateCertificateContext(X509_ASN_ENCODING,
     selfSignedCert, sizeof(selfSignedCert));
    ok(cert != NULL, "creating cert failed: %08x\n", GetLastError());
    /* Even in-memory certs are expected to have a store associated with them */
    ok(cert->hCertStore != NULL, "expected created cert to have a store\n");
    /* The cert doesn't have the archived property set (which would imply it
     * doesn't show up in enumerations.)
     */
    size = 0;
    ret = CertGetCertificateContextProperty(cert, CERT_ARCHIVED_PROP_ID,
     NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_NOT_FOUND,
       "expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());
    /* Strangely, enumerating the certs in the store finds none. */
    enumCert = NULL;
    count = 0;
    while ((enumCert = CertEnumCertificatesInStore(cert->hCertStore, enumCert)))
        count++;
    ok(!count, "expected 0, got %d\n", count);
    CertFreeCertificateContext(cert);
}

static void testDupCert(void)
{
    PCCERT_CONTEXT context, dupContext, storeContext, storeContext2, context2;
    HCERTSTORE store, store2;
    BOOL ret;

    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(store != NULL, "CertOpenStore failed: %d\n", GetLastError());
    if (!store)
        return;

    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     bigCert, sizeof(bigCert), CERT_STORE_ADD_ALWAYS, &context);
    ok(ret || broken(GetLastError() == OSS_DATA_ERROR /* win98 */),
     "CertAddEncodedCertificateToStore failed: %08x\n", GetLastError());
    if (!ret && GetLastError() == OSS_DATA_ERROR)
    {
        skip("bigCert can't be decoded, skipping tests\n");
        return;
    }
    ok(context != NULL, "Expected a valid cert context\n");
    if (context)
    {
        ok(context->cbCertEncoded == sizeof(bigCert),
         "Wrong cert size %d\n", context->cbCertEncoded);
        ok(!memcmp(context->pbCertEncoded, bigCert, sizeof(bigCert)),
         "Unexpected encoded cert in context\n");
        ok(context->hCertStore == store, "Unexpected store\n");

        dupContext = CertDuplicateCertificateContext(context);
        ok(dupContext != NULL, "Expected valid duplicate\n");
        /* Not only is it a duplicate, it's identical: the address is the
         * same.
         */
        ok(dupContext == context, "Expected identical context addresses\n");
        CertFreeCertificateContext(dupContext);
        CertFreeCertificateContext(context);
    }
    CertCloseStore(store, 0);

    context = CertCreateCertificateContext(X509_ASN_ENCODING, bigCert, sizeof(bigCert));
    ok(context != NULL, "CertCreateCertificateContext failed\n");

    dupContext = CertDuplicateCertificateContext(context);
    ok(dupContext == context, "context != dupContext\n");

    ret = CertFreeCertificateContext(dupContext);
    ok(ret, "CertFreeCertificateContext failed\n");

    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(store != NULL, "CertOpenStore failed: %d\n", GetLastError());

    ret = CertAddCertificateContextToStore(store, context, CERT_STORE_ADD_NEW, &storeContext);
    ok(ret, "CertAddCertificateContextToStore failed\n");
    ok(storeContext != NULL && storeContext != context, "unexpected storeContext\n");
    ok(storeContext->hCertStore == store, "unexpected hCertStore\n");

    ok(storeContext->pbCertEncoded != context->pbCertEncoded, "unexpected pbCertEncoded\n");
    ok(storeContext->cbCertEncoded == context->cbCertEncoded, "unexpected cbCertEncoded\n");
    ok(storeContext->pCertInfo != context->pCertInfo, "unexpected pCertInfo\n");

    store2 = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(store2 != NULL, "CertOpenStore failed: %d\n", GetLastError());

    ret = CertAddCertificateContextToStore(store2, storeContext, CERT_STORE_ADD_NEW, &storeContext2);
    ok(ret, "CertAddCertificateContextToStore failed\n");
    ok(storeContext2 != NULL && storeContext2 != storeContext, "unexpected storeContext\n");
    ok(storeContext2->hCertStore == store2, "unexpected hCertStore\n");

    ok(storeContext2->pbCertEncoded != storeContext->pbCertEncoded, "unexpected pbCertEncoded\n");
    ok(storeContext2->cbCertEncoded == storeContext->cbCertEncoded, "unexpected cbCertEncoded\n");
    ok(storeContext2->pCertInfo != storeContext->pCertInfo, "unexpected pCertInfo\n");

    CertFreeCertificateContext(storeContext2);
    CertFreeCertificateContext(storeContext);

    context2 = CertCreateCertificateContext(X509_ASN_ENCODING, certWithUsage, sizeof(certWithUsage));
    ok(context2 != NULL, "CertCreateCertificateContext failed\n");

    ok(context2->hCertStore == context->hCertStore, "Unexpected hCertStore\n");

    CertFreeCertificateContext(context2);
    ret = CertFreeCertificateContext(context);
    ok(ret, "CertFreeCertificateContext failed\n");

    CertCloseStore(store, 0);
    CertCloseStore(store2, 0);

    SetLastError(0xdeadbeef);
    context = CertDuplicateCertificateContext(NULL);
    ok(context == NULL, "Expected context to be NULL\n");

    ret = CertFreeCertificateContext(NULL);
    ok(ret, "CertFreeCertificateContext failed\n");
}

static void testLinkCert(void)
{
    const CERT_CONTEXT *context, *link;
    HCERTSTORE store;
    BOOL ret;

    context = CertCreateCertificateContext(X509_ASN_ENCODING, bigCert, sizeof(bigCert));
    ok(context != NULL, "CertCreateCertificateContext failed\n");

    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(store != NULL, "CertOpenStore failed: %d\n", GetLastError());

    ret = CertAddCertificateLinkToStore(store, context, CERT_STORE_ADD_NEW, &link);
    ok(ret, "CertAddCertificateContextToStore failed\n");
    ok(link != NULL && link != context, "unexpected storeContext\n");
    ok(link->hCertStore == store, "unexpected hCertStore\n");

    ok(link->pbCertEncoded == context->pbCertEncoded, "unexpected pbCertEncoded\n");
    ok(link->cbCertEncoded == context->cbCertEncoded, "unexpected cbCertEncoded\n");
    ok(link->pCertInfo == context->pCertInfo, "unexpected pCertInfo\n");

    CertFreeCertificateContext(link);
    CertFreeCertificateContext(context);
    CertCloseStore(store, 0);
}

static BYTE subjectName3[] = { 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06,
 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x52, 0x6f, 0x62, 0x20, 0x20, 0x4c, 0x61,
 0x6e, 0x67, 0x00 };
static const BYTE iTunesCert0[] = {
0x30,0x82,0x03,0xc4,0x30,0x82,0x03,0x2d,0xa0,0x03,0x02,0x01,0x02,0x02,0x10,
0x47,0xbf,0x19,0x95,0xdf,0x8d,0x52,0x46,0x43,0xf7,0xdb,0x6d,0x48,0x0d,0x31,
0xa4,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,
0x00,0x30,0x81,0x8b,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,
0x5a,0x41,0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x08,0x13,0x0c,0x57,0x65,
0x73,0x74,0x65,0x72,0x6e,0x20,0x43,0x61,0x70,0x65,0x31,0x14,0x30,0x12,0x06,
0x03,0x55,0x04,0x07,0x13,0x0b,0x44,0x75,0x72,0x62,0x61,0x6e,0x76,0x69,0x6c,
0x6c,0x65,0x31,0x0f,0x30,0x0d,0x06,0x03,0x55,0x04,0x0a,0x13,0x06,0x54,0x68,
0x61,0x77,0x74,0x65,0x31,0x1d,0x30,0x1b,0x06,0x03,0x55,0x04,0x0b,0x13,0x14,
0x54,0x68,0x61,0x77,0x74,0x65,0x20,0x43,0x65,0x72,0x74,0x69,0x66,0x69,0x63,
0x61,0x74,0x69,0x6f,0x6e,0x31,0x1f,0x30,0x1d,0x06,0x03,0x55,0x04,0x03,0x13,
0x16,0x54,0x68,0x61,0x77,0x74,0x65,0x20,0x54,0x69,0x6d,0x65,0x73,0x74,0x61,
0x6d,0x70,0x69,0x6e,0x67,0x20,0x43,0x41,0x30,0x1e,0x17,0x0d,0x30,0x33,0x31,
0x32,0x30,0x34,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,0x31,0x33,0x31,
0x32,0x30,0x33,0x32,0x33,0x35,0x39,0x35,0x39,0x5a,0x30,0x53,0x31,0x0b,0x30,
0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x17,0x30,0x15,0x06,
0x03,0x55,0x04,0x0a,0x13,0x0e,0x56,0x65,0x72,0x69,0x53,0x69,0x67,0x6e,0x2c,
0x20,0x49,0x6e,0x63,0x2e,0x31,0x2b,0x30,0x29,0x06,0x03,0x55,0x04,0x03,0x13,
0x22,0x56,0x65,0x72,0x69,0x53,0x69,0x67,0x6e,0x20,0x54,0x69,0x6d,0x65,0x20,
0x53,0x74,0x61,0x6d,0x70,0x69,0x6e,0x67,0x20,0x53,0x65,0x72,0x76,0x69,0x63,
0x65,0x73,0x20,0x43,0x41,0x30,0x82,0x01,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,
0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x01,0x0f,0x00,0x30,
0x82,0x01,0x0a,0x02,0x82,0x01,0x01,0x00,0xa9,0xca,0xb2,0xa4,0xcc,0xcd,0x20,
0xaf,0x0a,0x7d,0x89,0xac,0x87,0x75,0xf0,0xb4,0x4e,0xf1,0xdf,0xc1,0x0f,0xbf,
0x67,0x61,0xbd,0xa3,0x64,0x1c,0xda,0xbb,0xf9,0xca,0x33,0xab,0x84,0x30,0x89,
0x58,0x7e,0x8c,0xdb,0x6b,0xdd,0x36,0x9e,0x0f,0xbf,0xd1,0xec,0x78,0xf2,0x77,
0xa6,0x7e,0x6f,0x3c,0xbf,0x93,0xaf,0x0d,0xba,0x68,0xf4,0x6c,0x94,0xca,0xbd,
0x52,0x2d,0xab,0x48,0x3d,0xf5,0xb6,0xd5,0x5d,0x5f,0x1b,0x02,0x9f,0xfa,0x2f,
0x6b,0x1e,0xa4,0xf7,0xa3,0x9a,0xa6,0x1a,0xc8,0x02,0xe1,0x7f,0x4c,0x52,0xe3,
0x0e,0x60,0xec,0x40,0x1c,0x7e,0xb9,0x0d,0xde,0x3f,0xc7,0xb4,0xdf,0x87,0xbd,
0x5f,0x7a,0x6a,0x31,0x2e,0x03,0x99,0x81,0x13,0xa8,0x47,0x20,0xce,0x31,0x73,
0x0d,0x57,0x2d,0xcd,0x78,0x34,0x33,0x95,0x12,0x99,0x12,0xb9,0xde,0x68,0x2f,
0xaa,0xe6,0xe3,0xc2,0x8a,0x8c,0x2a,0xc3,0x8b,0x21,0x87,0x66,0xbd,0x83,0x58,
0x57,0x6f,0x75,0xbf,0x3c,0xaa,0x26,0x87,0x5d,0xca,0x10,0x15,0x3c,0x9f,0x84,
0xea,0x54,0xc1,0x0a,0x6e,0xc4,0xfe,0xc5,0x4a,0xdd,0xb9,0x07,0x11,0x97,0x22,
0x7c,0xdb,0x3e,0x27,0xd1,0x1e,0x78,0xec,0x9f,0x31,0xc9,0xf1,0xe6,0x22,0x19,
0xdb,0xc4,0xb3,0x47,0x43,0x9a,0x1a,0x5f,0xa0,0x1e,0x90,0xe4,0x5e,0xf5,0xee,
0x7c,0xf1,0x7d,0xab,0x62,0x01,0x8f,0xf5,0x4d,0x0b,0xde,0xd0,0x22,0x56,0xa8,
0x95,0xcd,0xae,0x88,0x76,0xae,0xee,0xba,0x0d,0xf3,0xe4,0x4d,0xd9,0xa0,0xfb,
0x68,0xa0,0xae,0x14,0x3b,0xb3,0x87,0xc1,0xbb,0x02,0x03,0x01,0x00,0x01,0xa3,
0x81,0xdb,0x30,0x81,0xd8,0x30,0x34,0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,
0x01,0x01,0x04,0x28,0x30,0x26,0x30,0x24,0x06,0x08,0x2b,0x06,0x01,0x05,0x05,
0x07,0x30,0x01,0x86,0x18,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x6f,0x63,0x73,
0x70,0x2e,0x76,0x65,0x72,0x69,0x73,0x69,0x67,0x6e,0x2e,0x63,0x6f,0x6d,0x30,
0x12,0x06,0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,0x01,0x01,
0xff,0x02,0x01,0x00,0x30,0x41,0x06,0x03,0x55,0x1d,0x1f,0x04,0x3a,0x30,0x38,
0x30,0x36,0xa0,0x34,0xa0,0x32,0x86,0x30,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,
0x63,0x72,0x6c,0x2e,0x76,0x65,0x72,0x69,0x73,0x69,0x67,0x6e,0x2e,0x63,0x6f,
0x6d,0x2f,0x54,0x68,0x61,0x77,0x74,0x65,0x54,0x69,0x6d,0x65,0x73,0x74,0x61,
0x6d,0x70,0x69,0x6e,0x67,0x43,0x41,0x2e,0x63,0x72,0x6c,0x30,0x13,0x06,0x03,
0x55,0x1d,0x25,0x04,0x0c,0x30,0x0a,0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,
0x03,0x08,0x30,0x0e,0x06,0x03,0x55,0x1d,0x0f,0x01,0x01,0xff,0x04,0x04,0x03,
0x02,0x01,0x06,0x30,0x24,0x06,0x03,0x55,0x1d,0x11,0x04,0x1d,0x30,0x1b,0xa4,
0x19,0x30,0x17,0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x03,0x13,0x0c,0x54,
0x53,0x41,0x32,0x30,0x34,0x38,0x2d,0x31,0x2d,0x35,0x33,0x30,0x0d,0x06,0x09,
0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,0x00,0x03,0x81,0x81,0x00,
0x4a,0x6b,0xf9,0xea,0x58,0xc2,0x44,0x1c,0x31,0x89,0x79,0x99,0x2b,0x96,0xbf,
0x82,0xac,0x01,0xd6,0x1c,0x4c,0xcd,0xb0,0x8a,0x58,0x6e,0xdf,0x08,0x29,0xa3,
0x5e,0xc8,0xca,0x93,0x13,0xe7,0x04,0x52,0x0d,0xef,0x47,0x27,0x2f,0x00,0x38,
0xb0,0xe4,0xc9,0x93,0x4e,0x9a,0xd4,0x22,0x62,0x15,0xf7,0x3f,0x37,0x21,0x4f,
0x70,0x31,0x80,0xf1,0x8b,0x38,0x87,0xb3,0xe8,0xe8,0x97,0x00,0xfe,0xcf,0x55,
0x96,0x4e,0x24,0xd2,0xa9,0x27,0x4e,0x7a,0xae,0xb7,0x61,0x41,0xf3,0x2a,0xce,
0xe7,0xc9,0xd9,0x5e,0xdd,0xbb,0x2b,0x85,0x3e,0xb5,0x9d,0xb5,0xd9,0xe1,0x57,
0xff,0xbe,0xb4,0xc5,0x7e,0xf5,0xcf,0x0c,0x9e,0xf0,0x97,0xfe,0x2b,0xd3,0x3b,
0x52,0x1b,0x1b,0x38,0x27,0xf7,0x3f,0x4a };
static const BYTE iTunesCert1[] = {
0x30,0x82,0x03,0xff,0x30,0x82,0x02,0xe7,0xa0,0x03,0x02,0x01,0x02,0x02,0x10,
0x0d,0xe9,0x2b,0xf0,0xd4,0xd8,0x29,0x88,0x18,0x32,0x05,0x09,0x5e,0x9a,0x76,
0x88,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,
0x00,0x30,0x53,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,
0x53,0x31,0x17,0x30,0x15,0x06,0x03,0x55,0x04,0x0a,0x13,0x0e,0x56,0x65,0x72,
0x69,0x53,0x69,0x67,0x6e,0x2c,0x20,0x49,0x6e,0x63,0x2e,0x31,0x2b,0x30,0x29,
0x06,0x03,0x55,0x04,0x03,0x13,0x22,0x56,0x65,0x72,0x69,0x53,0x69,0x67,0x6e,
0x20,0x54,0x69,0x6d,0x65,0x20,0x53,0x74,0x61,0x6d,0x70,0x69,0x6e,0x67,0x20,
0x53,0x65,0x72,0x76,0x69,0x63,0x65,0x73,0x20,0x43,0x41,0x30,0x1e,0x17,0x0d,
0x30,0x33,0x31,0x32,0x30,0x34,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,
0x30,0x38,0x31,0x32,0x30,0x33,0x32,0x33,0x35,0x39,0x35,0x39,0x5a,0x30,0x57,
0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x17,
0x30,0x15,0x06,0x03,0x55,0x04,0x0a,0x13,0x0e,0x56,0x65,0x72,0x69,0x53,0x69,
0x67,0x6e,0x2c,0x20,0x49,0x6e,0x63,0x2e,0x31,0x2f,0x30,0x2d,0x06,0x03,0x55,
0x04,0x03,0x13,0x26,0x56,0x65,0x72,0x69,0x53,0x69,0x67,0x6e,0x20,0x54,0x69,
0x6d,0x65,0x20,0x53,0x74,0x61,0x6d,0x70,0x69,0x6e,0x67,0x20,0x53,0x65,0x72,
0x76,0x69,0x63,0x65,0x73,0x20,0x53,0x69,0x67,0x6e,0x65,0x72,0x30,0x82,0x01,
0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,
0x00,0x03,0x82,0x01,0x0f,0x00,0x30,0x82,0x01,0x0a,0x02,0x82,0x01,0x01,0x00,
0xb2,0x50,0x28,0x48,0xdd,0xd3,0x68,0x7a,0x84,0x18,0x44,0x66,0x75,0x5d,0x7e,
0xc4,0xb8,0x9f,0x63,0x26,0xff,0x3d,0x43,0x9c,0x7c,0x11,0x38,0x10,0x25,0x55,
0x73,0xd9,0x75,0x27,0x69,0xfd,0x4e,0xb9,0x20,0x5c,0xd3,0x0a,0xf9,0xa0,0x1b,
0x2a,0xed,0x55,0x56,0x21,0x61,0xd8,0x1e,0xdb,0xe4,0xbc,0x33,0x6b,0xc7,0xef,
0xdd,0xa3,0x37,0x65,0x8e,0x1b,0x93,0x0c,0xb6,0x53,0x1e,0x5c,0x7c,0x66,0x35,
0x5f,0x05,0x8a,0x45,0xfe,0x76,0x4e,0xdf,0x53,0x80,0xa2,0x81,0x20,0x9d,0xae,
0x88,0x5c,0xa2,0x08,0xf7,0xe5,0x30,0xf9,0xee,0x22,0x37,0x4c,0x42,0x0a,0xce,
0xdf,0xc6,0x1f,0xc4,0xd6,0x55,0xe9,0x81,0x3f,0xb5,0x52,0xa3,0x2c,0xaa,0x01,
0x7a,0xf2,0xa2,0xaa,0x8d,0x35,0xfe,0x9f,0xe6,0x5d,0x6a,0x05,0x9f,0x3d,0x6b,
0xe3,0xbf,0x96,0xc0,0xfe,0xcc,0x60,0xf9,0x40,0xe7,0x07,0xa0,0x44,0xeb,0x81,
0x51,0x6e,0xa5,0x2a,0xf2,0xb6,0x8a,0x10,0x28,0xed,0x8f,0xdc,0x06,0xa0,0x86,
0x50,0x9a,0x7b,0x4a,0x08,0x0d,0x30,0x1d,0xca,0x10,0x9e,0x6b,0xf7,0xe9,0x58,
0xae,0x04,0xa9,0x40,0x99,0xb2,0x28,0xe8,0x8f,0x16,0xac,0x3c,0xe3,0x53,0x6f,
0x4b,0xd3,0x35,0x9d,0xb5,0x6f,0x64,0x1d,0xb3,0x96,0x2c,0xbb,0x3d,0xe7,0x79,
0xeb,0x6d,0x7a,0xf9,0x16,0xe6,0x26,0xad,0xaf,0xef,0x99,0x53,0xb7,0x40,0x2c,
0x95,0xb8,0x79,0xaa,0xfe,0xd4,0x52,0xab,0x29,0x74,0x7e,0x42,0xec,0x39,0x1e,
0xa2,0x6a,0x16,0xe6,0x59,0xbb,0x24,0x68,0xd8,0x00,0x80,0x43,0x10,0x87,0x80,
0x6b,0x02,0x03,0x01,0x00,0x01,0xa3,0x81,0xca,0x30,0x81,0xc7,0x30,0x34,0x06,
0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x01,0x01,0x04,0x28,0x30,0x26,0x30,0x24,
0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x86,0x18,0x68,0x74,0x74,
0x70,0x3a,0x2f,0x2f,0x6f,0x63,0x73,0x70,0x2e,0x76,0x65,0x72,0x69,0x73,0x69,
0x67,0x6e,0x2e,0x63,0x6f,0x6d,0x30,0x0c,0x06,0x03,0x55,0x1d,0x13,0x01,0x01,
0xff,0x04,0x02,0x30,0x00,0x30,0x33,0x06,0x03,0x55,0x1d,0x1f,0x04,0x2c,0x30,
0x2a,0x30,0x28,0xa0,0x26,0xa0,0x24,0x86,0x22,0x68,0x74,0x74,0x70,0x3a,0x2f,
0x2f,0x63,0x72,0x6c,0x2e,0x76,0x65,0x72,0x69,0x73,0x69,0x67,0x6e,0x2e,0x63,
0x6f,0x6d,0x2f,0x74,0x73,0x73,0x2d,0x63,0x61,0x2e,0x63,0x72,0x6c,0x30,0x16,
0x06,0x03,0x55,0x1d,0x25,0x01,0x01,0xff,0x04,0x0c,0x30,0x0a,0x06,0x08,0x2b,
0x06,0x01,0x05,0x05,0x07,0x03,0x08,0x30,0x0e,0x06,0x03,0x55,0x1d,0x0f,0x01,
0x01,0xff,0x04,0x04,0x03,0x02,0x06,0xc0,0x30,0x24,0x06,0x03,0x55,0x1d,0x11,
0x04,0x1d,0x30,0x1b,0xa4,0x19,0x30,0x17,0x31,0x15,0x30,0x13,0x06,0x03,0x55,
0x04,0x03,0x13,0x0c,0x54,0x53,0x41,0x32,0x30,0x34,0x38,0x2d,0x31,0x2d,0x35,
0x34,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,
0x00,0x03,0x82,0x01,0x01,0x00,0x87,0x78,0x70,0xda,0x4e,0x52,0x01,0x20,0x5b,
0xe0,0x79,0xc9,0x82,0x30,0xc4,0xfd,0xb9,0x19,0x96,0xbd,0x91,0x00,0xc3,0xbd,
0xcd,0xcd,0xc6,0xf4,0x0e,0xd8,0xff,0xf9,0x4d,0xc0,0x33,0x62,0x30,0x11,0xc5,
0xf5,0x74,0x1b,0xd4,0x92,0xde,0x5f,0x9c,0x20,0x13,0xb1,0x7c,0x45,0xbe,0x50,
0xcd,0x83,0xe7,0x80,0x17,0x83,0xa7,0x27,0x93,0x67,0x13,0x46,0xfb,0xca,0xb8,
0x98,0x41,0x03,0xcc,0x9b,0x51,0x5b,0x05,0x8b,0x7f,0xa8,0x6f,0xf3,0x1b,0x50,
0x1b,0x24,0x2e,0xf2,0x69,0x8d,0x6c,0x22,0xf7,0xbb,0xca,0x16,0x95,0xed,0x0c,
0x74,0xc0,0x68,0x77,0xd9,0xeb,0x99,0x62,0x87,0xc1,0x73,0x90,0xf8,0x89,0x74,
0x7a,0x23,0xab,0xa3,0x98,0x7b,0x97,0xb1,0xf7,0x8f,0x29,0x71,0x4d,0x2e,0x75,
0x1b,0x48,0x41,0xda,0xf0,0xb5,0x0d,0x20,0x54,0xd6,0x77,0xa0,0x97,0x82,0x63,
0x69,0xfd,0x09,0xcf,0x8a,0xf0,0x75,0xbb,0x09,0x9b,0xd9,0xf9,0x11,0x55,0x26,
0x9a,0x61,0x32,0xbe,0x7a,0x02,0xb0,0x7b,0x86,0xbe,0xa2,0xc3,0x8b,0x22,0x2c,
0x78,0xd1,0x35,0x76,0xbc,0x92,0x73,0x5c,0xf9,0xb9,0xe6,0x4c,0x15,0x0a,0x23,
0xcc,0xe4,0xd2,0xd4,0x34,0x2e,0x49,0x40,0x15,0x3c,0x0f,0x60,0x7a,0x24,0xc6,
0xa5,0x66,0xef,0x96,0xcf,0x70,0xeb,0x3e,0xe7,0xf4,0x0d,0x7e,0xdc,0xd1,0x7c,
0xa3,0x76,0x71,0x69,0xc1,0x9c,0x4f,0x47,0x30,0x35,0x21,0xb1,0xa2,0xaf,0x1a,
0x62,0x3c,0x2b,0xd9,0x8e,0xaa,0x2a,0x07,0x7b,0xd8,0x18,0xb3,0x5c,0x7b,0xe2,
0x9d,0xa5,0x6f,0xfe,0x3c,0x89,0xad };
static const BYTE iTunesCert2[] = {
0x30,0x82,0x04,0xbf,0x30,0x82,0x04,0x28,0xa0,0x03,0x02,0x01,0x02,0x02,0x10,
0x41,0x91,0xa1,0x5a,0x39,0x78,0xdf,0xcf,0x49,0x65,0x66,0x38,0x1d,0x4c,0x75,
0xc2,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,
0x00,0x30,0x5f,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,
0x53,0x31,0x17,0x30,0x15,0x06,0x03,0x55,0x04,0x0a,0x13,0x0e,0x56,0x65,0x72,
0x69,0x53,0x69,0x67,0x6e,0x2c,0x20,0x49,0x6e,0x63,0x2e,0x31,0x37,0x30,0x35,
0x06,0x03,0x55,0x04,0x0b,0x13,0x2e,0x43,0x6c,0x61,0x73,0x73,0x20,0x33,0x20,
0x50,0x75,0x62,0x6c,0x69,0x63,0x20,0x50,0x72,0x69,0x6d,0x61,0x72,0x79,0x20,
0x43,0x65,0x72,0x74,0x69,0x66,0x69,0x63,0x61,0x74,0x69,0x6f,0x6e,0x20,0x41,
0x75,0x74,0x68,0x6f,0x72,0x69,0x74,0x79,0x30,0x1e,0x17,0x0d,0x30,0x34,0x30,
0x37,0x31,0x36,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,0x31,0x34,0x30,
0x37,0x31,0x35,0x32,0x33,0x35,0x39,0x35,0x39,0x5a,0x30,0x81,0xb4,0x31,0x0b,
0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x17,0x30,0x15,
0x06,0x03,0x55,0x04,0x0a,0x13,0x0e,0x56,0x65,0x72,0x69,0x53,0x69,0x67,0x6e,
0x2c,0x20,0x49,0x6e,0x63,0x2e,0x31,0x1f,0x30,0x1d,0x06,0x03,0x55,0x04,0x0b,
0x13,0x16,0x56,0x65,0x72,0x69,0x53,0x69,0x67,0x6e,0x20,0x54,0x72,0x75,0x73,
0x74,0x20,0x4e,0x65,0x74,0x77,0x6f,0x72,0x6b,0x31,0x3b,0x30,0x39,0x06,0x03,
0x55,0x04,0x0b,0x13,0x32,0x54,0x65,0x72,0x6d,0x73,0x20,0x6f,0x66,0x20,0x75,
0x73,0x65,0x20,0x61,0x74,0x20,0x68,0x74,0x74,0x70,0x73,0x3a,0x2f,0x2f,0x77,
0x77,0x77,0x2e,0x76,0x65,0x72,0x69,0x73,0x69,0x67,0x6e,0x2e,0x63,0x6f,0x6d,
0x2f,0x72,0x70,0x61,0x20,0x28,0x63,0x29,0x30,0x34,0x31,0x2e,0x30,0x2c,0x06,
0x03,0x55,0x04,0x03,0x13,0x25,0x56,0x65,0x72,0x69,0x53,0x69,0x67,0x6e,0x20,
0x43,0x6c,0x61,0x73,0x73,0x20,0x33,0x20,0x43,0x6f,0x64,0x65,0x20,0x53,0x69,
0x67,0x6e,0x69,0x6e,0x67,0x20,0x32,0x30,0x30,0x34,0x20,0x43,0x41,0x30,0x82,
0x01,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,
0x05,0x00,0x03,0x82,0x01,0x0f,0x00,0x30,0x82,0x01,0x0a,0x02,0x82,0x01,0x01,
0x00,0xbe,0xbc,0xee,0xbc,0x7e,0xef,0x83,0xeb,0xe0,0x37,0x4f,0xfb,0x03,0x10,
0x38,0xbe,0x08,0xd2,0x8c,0x7d,0x9d,0xfa,0x92,0x7f,0x19,0x0c,0xc2,0x6b,0xee,
0x42,0x52,0x8c,0xde,0xd3,0x1c,0x48,0x13,0x25,0xea,0xc1,0x63,0x7a,0xf9,0x51,
0x65,0xee,0xd3,0xaa,0x3b,0xf5,0xf0,0x94,0x9c,0x2b,0xfb,0xf2,0x66,0xd4,0x24,
0xda,0xf7,0xf5,0x9f,0x6e,0x19,0x39,0x36,0xbc,0xd0,0xa3,0x76,0x08,0x1e,0x22,
0x27,0x24,0x6c,0x38,0x91,0x27,0xe2,0x84,0x49,0xae,0x1b,0x8a,0xa1,0xfd,0x25,
0x82,0x2c,0x10,0x30,0xe8,0x71,0xab,0x28,0xe8,0x77,0x4a,0x51,0xf1,0xec,0xcd,
0xf8,0xf0,0x54,0xd4,0x6f,0xc0,0xe3,0x6d,0x0a,0x8f,0xd9,0xd8,0x64,0x8d,0x63,
0xb2,0x2d,0x4e,0x27,0xf6,0x85,0x0e,0xfe,0x6d,0xe3,0x29,0x99,0xe2,0x85,0x47,
0x7c,0x2d,0x86,0x7f,0xe8,0x57,0x8f,0xad,0x67,0xc2,0x33,0x32,0x91,0x13,0x20,
0xfc,0xa9,0x23,0x14,0x9a,0x6d,0xc2,0x84,0x4b,0x76,0x68,0x04,0xd5,0x71,0x2c,
0x5d,0x21,0xfa,0x88,0x0d,0x26,0xfd,0x1f,0x2d,0x91,0x2b,0xe7,0x01,0x55,0x4d,
0xf2,0x6d,0x35,0x28,0x82,0xdf,0xd9,0x6b,0x5c,0xb6,0xd6,0xd9,0xaa,0x81,0xfd,
0x5f,0xcd,0x83,0xba,0x63,0x9d,0xd0,0x22,0xfc,0xa9,0x3b,0x42,0x69,0xb2,0x8e,
0x3a,0xb5,0xbc,0xb4,0x9e,0x0f,0x5e,0xc4,0xea,0x2c,0x82,0x8b,0x28,0xfd,0x53,
0x08,0x96,0xdd,0xb5,0x01,0x20,0xd1,0xf9,0xa5,0x18,0xe7,0xc0,0xee,0x51,0x70,
0x37,0xe1,0xb6,0x05,0x48,0x52,0x48,0x6f,0x38,0xea,0xc3,0xe8,0x6c,0x7b,0x44,
0x84,0xbb,0x02,0x03,0x01,0x00,0x01,0xa3,0x82,0x01,0xa0,0x30,0x82,0x01,0x9c,
0x30,0x12,0x06,0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,0x01,
0x01,0xff,0x02,0x01,0x00,0x30,0x44,0x06,0x03,0x55,0x1d,0x20,0x04,0x3d,0x30,
0x3b,0x30,0x39,0x06,0x0b,0x60,0x86,0x48,0x01,0x86,0xf8,0x45,0x01,0x07,0x17,
0x03,0x30,0x2a,0x30,0x28,0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x02,0x01,
0x16,0x1c,0x68,0x74,0x74,0x70,0x73,0x3a,0x2f,0x2f,0x77,0x77,0x77,0x2e,0x76,
0x65,0x72,0x69,0x73,0x69,0x67,0x6e,0x2e,0x63,0x6f,0x6d,0x2f,0x72,0x70,0x61,
0x30,0x31,0x06,0x03,0x55,0x1d,0x1f,0x04,0x2a,0x30,0x28,0x30,0x26,0xa0,0x24,
0xa0,0x22,0x86,0x20,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x63,0x72,0x6c,0x2e,
0x76,0x65,0x72,0x69,0x73,0x69,0x67,0x6e,0x2e,0x63,0x6f,0x6d,0x2f,0x70,0x63,
0x61,0x33,0x2e,0x63,0x72,0x6c,0x30,0x1d,0x06,0x03,0x55,0x1d,0x25,0x04,0x16,
0x30,0x14,0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x02,0x06,0x08,0x2b,
0x06,0x01,0x05,0x05,0x07,0x03,0x03,0x30,0x0e,0x06,0x03,0x55,0x1d,0x0f,0x01,
0x01,0xff,0x04,0x04,0x03,0x02,0x01,0x06,0x30,0x11,0x06,0x09,0x60,0x86,0x48,
0x01,0x86,0xf8,0x42,0x01,0x01,0x04,0x04,0x03,0x02,0x00,0x01,0x30,0x29,0x06,
0x03,0x55,0x1d,0x11,0x04,0x22,0x30,0x20,0xa4,0x1e,0x30,0x1c,0x31,0x1a,0x30,
0x18,0x06,0x03,0x55,0x04,0x03,0x13,0x11,0x43,0x6c,0x61,0x73,0x73,0x33,0x43,
0x41,0x32,0x30,0x34,0x38,0x2d,0x31,0x2d,0x34,0x33,0x30,0x1d,0x06,0x03,0x55,
0x1d,0x0e,0x04,0x16,0x04,0x14,0x08,0xf5,0x51,0xe8,0xfb,0xfe,0x3d,0x3d,0x64,
0x36,0x7c,0x68,0xcf,0x5b,0x78,0xa8,0xdf,0xb9,0xc5,0x37,0x30,0x81,0x80,0x06,
0x03,0x55,0x1d,0x23,0x04,0x79,0x30,0x77,0xa1,0x63,0xa4,0x61,0x30,0x5f,0x31,
0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x17,0x30,
0x15,0x06,0x03,0x55,0x04,0x0a,0x13,0x0e,0x56,0x65,0x72,0x69,0x53,0x69,0x67,
0x6e,0x2c,0x20,0x49,0x6e,0x63,0x2e,0x31,0x37,0x30,0x35,0x06,0x03,0x55,0x04,
0x0b,0x13,0x2e,0x43,0x6c,0x61,0x73,0x73,0x20,0x33,0x20,0x50,0x75,0x62,0x6c,
0x69,0x63,0x20,0x50,0x72,0x69,0x6d,0x61,0x72,0x79,0x20,0x43,0x65,0x72,0x74,
0x69,0x66,0x69,0x63,0x61,0x74,0x69,0x6f,0x6e,0x20,0x41,0x75,0x74,0x68,0x6f,
0x72,0x69,0x74,0x79,0x82,0x10,0x70,0xba,0xe4,0x1d,0x10,0xd9,0x29,0x34,0xb6,
0x38,0xca,0x7b,0x03,0xcc,0xba,0xbf,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x01,0x01,0x05,0x05,0x00,0x03,0x81,0x81,0x00,0xae,0x3a,0x17,0xb8,
0x4a,0x7b,0x55,0xfa,0x64,0x55,0xec,0x40,0xa4,0xed,0x49,0x41,0x90,0x99,0x9c,
0x89,0xbc,0xaf,0x2e,0x1d,0xca,0x78,0x23,0xf9,0x1c,0x19,0x0f,0x7f,0xeb,0x68,
0xbc,0x32,0xd9,0x88,0x38,0xde,0xdc,0x3f,0xd3,0x89,0xb4,0x3f,0xb1,0x82,0x96,
0xf1,0xa4,0x5a,0xba,0xed,0x2e,0x26,0xd3,0xde,0x7c,0x01,0x6e,0x00,0x0a,0x00,
0xa4,0x06,0x92,0x11,0x48,0x09,0x40,0xf9,0x1c,0x18,0x79,0x67,0x23,0x24,0xe0,
0xbb,0xd5,0xe1,0x50,0xae,0x1b,0xf5,0x0e,0xdd,0xe0,0x2e,0x81,0xcd,0x80,0xa3,
0x6c,0x52,0x4f,0x91,0x75,0x55,0x8a,0xba,0x22,0xf2,0xd2,0xea,0x41,0x75,0x88,
0x2f,0x63,0x55,0x7d,0x1e,0x54,0x5a,0x95,0x59,0xca,0xd9,0x34,0x81,0xc0,0x5f,
0x5e,0xf6,0x7a,0xb5 };
static const BYTE iTunesCert3[] = {
0x30,0x82,0x04,0xf1,0x30,0x82,0x03,0xd9,0xa0,0x03,0x02,0x01,0x02,0x02,0x10,
0x0f,0x1a,0xa0,0xe0,0x9b,0x9b,0x61,0xa6,0xb6,0xfe,0x40,0xd2,0xdf,0x6a,0xf6,
0x8d,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,
0x00,0x30,0x81,0xb4,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,
0x55,0x53,0x31,0x17,0x30,0x15,0x06,0x03,0x55,0x04,0x0a,0x13,0x0e,0x56,0x65,
0x72,0x69,0x53,0x69,0x67,0x6e,0x2c,0x20,0x49,0x6e,0x63,0x2e,0x31,0x1f,0x30,
0x1d,0x06,0x03,0x55,0x04,0x0b,0x13,0x16,0x56,0x65,0x72,0x69,0x53,0x69,0x67,
0x6e,0x20,0x54,0x72,0x75,0x73,0x74,0x20,0x4e,0x65,0x74,0x77,0x6f,0x72,0x6b,
0x31,0x3b,0x30,0x39,0x06,0x03,0x55,0x04,0x0b,0x13,0x32,0x54,0x65,0x72,0x6d,
0x73,0x20,0x6f,0x66,0x20,0x75,0x73,0x65,0x20,0x61,0x74,0x20,0x68,0x74,0x74,
0x70,0x73,0x3a,0x2f,0x2f,0x77,0x77,0x77,0x2e,0x76,0x65,0x72,0x69,0x73,0x69,
0x67,0x6e,0x2e,0x63,0x6f,0x6d,0x2f,0x72,0x70,0x61,0x20,0x28,0x63,0x29,0x30,
0x34,0x31,0x2e,0x30,0x2c,0x06,0x03,0x55,0x04,0x03,0x13,0x25,0x56,0x65,0x72,
0x69,0x53,0x69,0x67,0x6e,0x20,0x43,0x6c,0x61,0x73,0x73,0x20,0x33,0x20,0x43,
0x6f,0x64,0x65,0x20,0x53,0x69,0x67,0x6e,0x69,0x6e,0x67,0x20,0x32,0x30,0x30,
0x34,0x20,0x43,0x41,0x30,0x1e,0x17,0x0d,0x30,0x36,0x30,0x31,0x31,0x37,0x30,
0x30,0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,0x30,0x38,0x30,0x31,0x32,0x32,0x32,
0x33,0x35,0x39,0x35,0x39,0x5a,0x30,0x81,0xb4,0x31,0x0b,0x30,0x09,0x06,0x03,
0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,
0x08,0x13,0x0a,0x43,0x61,0x6c,0x69,0x66,0x6f,0x72,0x6e,0x69,0x61,0x31,0x12,
0x30,0x10,0x06,0x03,0x55,0x04,0x07,0x13,0x09,0x43,0x75,0x70,0x65,0x72,0x74,
0x69,0x6e,0x6f,0x31,0x1d,0x30,0x1b,0x06,0x03,0x55,0x04,0x0a,0x14,0x14,0x41,
0x70,0x70,0x6c,0x65,0x20,0x43,0x6f,0x6d,0x70,0x75,0x74,0x65,0x72,0x2c,0x20,
0x49,0x6e,0x63,0x2e,0x31,0x3e,0x30,0x3c,0x06,0x03,0x55,0x04,0x0b,0x13,0x35,
0x44,0x69,0x67,0x69,0x74,0x61,0x6c,0x20,0x49,0x44,0x20,0x43,0x6c,0x61,0x73,
0x73,0x20,0x33,0x20,0x2d,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,
0x20,0x53,0x6f,0x66,0x74,0x77,0x61,0x72,0x65,0x20,0x56,0x61,0x6c,0x69,0x64,
0x61,0x74,0x69,0x6f,0x6e,0x20,0x76,0x32,0x31,0x1d,0x30,0x1b,0x06,0x03,0x55,
0x04,0x03,0x14,0x14,0x41,0x70,0x70,0x6c,0x65,0x20,0x43,0x6f,0x6d,0x70,0x75,
0x74,0x65,0x72,0x2c,0x20,0x49,0x6e,0x63,0x2e,0x30,0x81,0x9f,0x30,0x0d,0x06,
0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x81,0x8d,
0x00,0x30,0x81,0x89,0x02,0x81,0x81,0x00,0xd3,0xab,0x3b,0x7f,0xec,0x48,0x84,
0xce,0xa8,0x1a,0x12,0xf3,0x3c,0x87,0xcb,0x24,0x58,0x96,0x02,0x87,0x66,0x49,
0xeb,0x89,0xee,0x79,0x44,0x70,0x8d,0xe7,0xd4,0x1f,0x30,0x92,0xc0,0x9c,0x35,
0x78,0xc0,0xaf,0x1c,0xb6,0x28,0xd3,0xe0,0xe0,0x9d,0xd3,0x49,0x76,0x73,0x57,
0x19,0x4d,0x8d,0x70,0x85,0x64,0x4d,0x1d,0xc6,0x02,0x3e,0xe5,0x2c,0x66,0x07,
0xd2,0x27,0x4b,0xd6,0xc8,0x3c,0x93,0xb6,0x15,0x0c,0xde,0x5b,0xd7,0x93,0xdd,
0xbe,0x85,0x62,0x34,0x17,0x8a,0x05,0x60,0xf0,0x8a,0x1c,0x5a,0x40,0x21,0x8d,
0x51,0x6c,0xb0,0x62,0xd8,0xb5,0xd4,0xf9,0xb1,0xd0,0x58,0x7a,0x7a,0x82,0x55,
0xb3,0xf9,0x53,0x71,0xde,0xd2,0xc9,0x37,0x8c,0xf6,0x5a,0x1f,0x2d,0xcd,0x7c,
0x67,0x02,0x03,0x01,0x00,0x01,0xa3,0x82,0x01,0x7f,0x30,0x82,0x01,0x7b,0x30,
0x09,0x06,0x03,0x55,0x1d,0x13,0x04,0x02,0x30,0x00,0x30,0x0e,0x06,0x03,0x55,
0x1d,0x0f,0x01,0x01,0xff,0x04,0x04,0x03,0x02,0x07,0x80,0x30,0x40,0x06,0x03,
0x55,0x1d,0x1f,0x04,0x39,0x30,0x37,0x30,0x35,0xa0,0x33,0xa0,0x31,0x86,0x2f,
0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x43,0x53,0x43,0x33,0x2d,0x32,0x30,0x30,
0x34,0x2d,0x63,0x72,0x6c,0x2e,0x76,0x65,0x72,0x69,0x73,0x69,0x67,0x6e,0x2e,
0x63,0x6f,0x6d,0x2f,0x43,0x53,0x43,0x33,0x2d,0x32,0x30,0x30,0x34,0x2e,0x63,
0x72,0x6c,0x30,0x44,0x06,0x03,0x55,0x1d,0x20,0x04,0x3d,0x30,0x3b,0x30,0x39,
0x06,0x0b,0x60,0x86,0x48,0x01,0x86,0xf8,0x45,0x01,0x07,0x17,0x03,0x30,0x2a,
0x30,0x28,0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x02,0x01,0x16,0x1c,0x68,
0x74,0x74,0x70,0x73,0x3a,0x2f,0x2f,0x77,0x77,0x77,0x2e,0x76,0x65,0x72,0x69,
0x73,0x69,0x67,0x6e,0x2e,0x63,0x6f,0x6d,0x2f,0x72,0x70,0x61,0x30,0x13,0x06,
0x03,0x55,0x1d,0x25,0x04,0x0c,0x30,0x0a,0x06,0x08,0x2b,0x06,0x01,0x05,0x05,
0x07,0x03,0x03,0x30,0x75,0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x01,0x01,
0x04,0x69,0x30,0x67,0x30,0x24,0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x30,
0x01,0x86,0x18,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x6f,0x63,0x73,0x70,0x2e,
0x76,0x65,0x72,0x69,0x73,0x69,0x67,0x6e,0x2e,0x63,0x6f,0x6d,0x30,0x3f,0x06,
0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x30,0x02,0x86,0x33,0x68,0x74,0x74,0x70,
0x3a,0x2f,0x2f,0x43,0x53,0x43,0x33,0x2d,0x32,0x30,0x30,0x34,0x2d,0x61,0x69,
0x61,0x2e,0x76,0x65,0x72,0x69,0x73,0x69,0x67,0x6e,0x2e,0x63,0x6f,0x6d,0x2f,
0x43,0x53,0x43,0x33,0x2d,0x32,0x30,0x30,0x34,0x2d,0x61,0x69,0x61,0x2e,0x63,
0x65,0x72,0x30,0x1f,0x06,0x03,0x55,0x1d,0x23,0x04,0x18,0x30,0x16,0x80,0x14,
0x08,0xf5,0x51,0xe8,0xfb,0xfe,0x3d,0x3d,0x64,0x36,0x7c,0x68,0xcf,0x5b,0x78,
0xa8,0xdf,0xb9,0xc5,0x37,0x30,0x11,0x06,0x09,0x60,0x86,0x48,0x01,0x86,0xf8,
0x42,0x01,0x01,0x04,0x04,0x03,0x02,0x04,0x10,0x30,0x16,0x06,0x0a,0x2b,0x06,
0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x1b,0x04,0x08,0x30,0x06,0x01,0x01,0x00,
0x01,0x01,0xff,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,
0x05,0x05,0x00,0x03,0x82,0x01,0x01,0x00,0x6a,0xa6,0x06,0xd0,0x33,0x18,0x64,
0xe2,0x69,0x82,0xee,0x6e,0x36,0x9e,0x9d,0x9a,0x0e,0x18,0xa8,0xac,0x9d,0x10,
0xed,0x01,0x3c,0xb9,0x61,0x04,0x62,0xf3,0x85,0x8f,0xcc,0x4f,0x2c,0x66,0x35,
0x54,0x25,0x45,0x8d,0x95,0x1c,0xd2,0x33,0xbe,0x2e,0xdd,0x7f,0x74,0xaf,0x03,
0x7b,0x86,0x63,0xb0,0xc9,0xe6,0xbd,0xc7,0x8e,0xde,0x03,0x18,0x98,0x82,0xc3,
0xbb,0xf8,0x15,0x99,0x1a,0xa9,0xdd,0xb9,0x5d,0xb9,0xbd,0x53,0x95,0x25,0x76,
0xfb,0x5c,0x53,0x90,0xea,0x01,0x0a,0xa0,0xb1,0xbf,0x09,0x1b,0x97,0x8f,0x40,
0xfa,0x85,0x12,0x74,0x01,0xdb,0xf6,0xdb,0x09,0xd6,0x5f,0x4f,0xd7,0x17,0xb4,
0xbf,0x9e,0x2f,0x86,0x52,0x5d,0x70,0x24,0x52,0x32,0x1e,0xa5,0x1d,0x39,0x8b,
0x66,0xf6,0xba,0x9b,0x69,0x8e,0x12,0x60,0xdb,0xb6,0xcf,0xe6,0x0d,0xd6,0x1c,
0x8f,0xd4,0x5b,0x4b,0x00,0xde,0x21,0x93,0xfb,0x6e,0xc7,0x3d,0xb4,0x66,0x0d,
0x29,0x0c,0x4e,0xe9,0x3f,0x94,0xd6,0xd6,0xdc,0xec,0xf8,0x53,0x3b,0x62,0xd5,
0x97,0x50,0x53,0x84,0x17,0xfe,0xe2,0xed,0x4c,0x23,0x0a,0x49,0xce,0x5b,0xe9,
0x70,0x31,0xc1,0x04,0x02,0x02,0x6c,0xb8,0x52,0xcd,0xc7,0x4e,0x70,0xb4,0x13,
0xd7,0xe0,0x92,0xba,0x44,0x1a,0x10,0x4c,0x6e,0x45,0xc6,0x86,0x04,0xc6,0x64,
0xd3,0x9c,0x6e,0xc1,0x9c,0xac,0x74,0x3d,0x77,0x06,0x5e,0x28,0x28,0x5c,0xf5,
0xe0,0x9c,0x19,0xd8,0xba,0x74,0x81,0x2d,0x67,0x77,0x93,0x8d,0xbf,0xd2,0x52,
0x00,0xe6,0xa5,0x38,0x4e,0x2e,0x73,0x66,0x7a };
static BYTE iTunesIssuer[] = {
0x30,0x81,0xb4,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,
0x13,0x02,0x55,0x53,0x31,0x17,0x30,0x15,0x06,0x03,0x55,0x04,
0x0a,0x13,0x0e,0x56,0x65,0x72,0x69,0x53,0x69,0x67,0x6e,0x2c,
0x20,0x49,0x6e,0x63,0x2e,0x31,0x1f,0x30,0x1d,0x06,0x03,0x55,
0x04,0x0b,0x13,0x16,0x56,0x65,0x72,0x69,0x53,0x69,0x67,0x6e,
0x20,0x54,0x72,0x75,0x73,0x74,0x20,0x4e,0x65,0x74,0x77,0x6f,
0x72,0x6b,0x31,0x3b,0x30,0x39,0x06,0x03,0x55,0x04,0x0b,0x13,
0x32,0x54,0x65,0x72,0x6d,0x73,0x20,0x6f,0x66,0x20,0x75,0x73,
0x65,0x20,0x61,0x74,0x20,0x68,0x74,0x74,0x70,0x73,0x3a,0x2f,
0x2f,0x77,0x77,0x77,0x2e,0x76,0x65,0x72,0x69,0x73,0x69,0x67,
0x6e,0x2e,0x63,0x6f,0x6d,0x2f,0x72,0x70,0x61,0x20,0x28,0x63,
0x29,0x30,0x34,0x31,0x2e,0x30,0x2c,0x06,0x03,0x55,0x04,0x03,
0x13,0x25,0x56,0x65,0x72,0x69,0x53,0x69,0x67,0x6e,0x20,0x43,
0x6c,0x61,0x73,0x73,0x20,0x33,0x20,0x43,0x6f,0x64,0x65,0x20,
0x53,0x69,0x67,0x6e,0x69,0x6e,0x67,0x20,0x32,0x30,0x30,0x34,
0x20,0x43,0x41 };
static BYTE iTunesSerialNum[] = {
0x8d,0xf6,0x6a,0xdf,0xd2,0x40,0xfe,0xb6,0xa6,0x61,0x9b,0x9b,
0xe0,0xa0,0x1a,0x0f };

static void testFindCert(void)
{
    HCERTSTORE store;
    PCCERT_CONTEXT context = NULL, subject;
    BOOL ret;
    CERT_INFO certInfo = { 0 };
    CRYPT_HASH_BLOB blob;
    BYTE otherSerialNumber[] = { 2 };
    DWORD count;
    static const WCHAR juan[] = { 'j','u','a','n',0 };
    static const WCHAR lang[] = { 'L','A','N','G',0 };
    static const WCHAR malcolm[] = { 'm','a','l','c','o','l','m',0 };

    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(store != NULL, "CertOpenStore failed: %d\n", GetLastError());
    if (!store)
        return;

    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     bigCert, sizeof(bigCert), CERT_STORE_ADD_NEW, NULL);
    ok(ret || broken(GetLastError() == OSS_DATA_ERROR /* win98 */),
     "CertAddEncodedCertificateToStore failed: %08x\n", GetLastError());
    if (!ret && GetLastError() == OSS_DATA_ERROR)
    {
        skip("bigCert can't be decoded, skipping tests\n");
        return;
    }
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     bigCert2, sizeof(bigCert2), CERT_STORE_ADD_NEW, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());
    /* This has the same name as bigCert */
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     certWithUsage, sizeof(certWithUsage), CERT_STORE_ADD_NEW, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());

    /* Crashes
    context = CertFindCertificateInStore(NULL, 0, 0, 0, NULL, NULL);
     */

    /* Check first cert's there, by issuer */
    certInfo.Subject.pbData = subjectName;
    certInfo.Subject.cbData = sizeof(subjectName);
    certInfo.SerialNumber.pbData = serialNum;
    certInfo.SerialNumber.cbData = sizeof(serialNum);
    context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
     CERT_FIND_ISSUER_NAME, &certInfo.Subject, NULL);
    ok(context != NULL, "CertFindCertificateInStore failed: %08x\n",
     GetLastError());
    if (context)
    {
        context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
         CERT_FIND_ISSUER_NAME, &certInfo.Subject, context);
        ok(context != NULL, "Expected more than one cert\n");
        if (context)
        {
            context = CertFindCertificateInStore(store, X509_ASN_ENCODING,
             0, CERT_FIND_ISSUER_NAME, &certInfo.Subject, context);
            ok(context == NULL, "Expected precisely two certs\n");
        }
    }

    /* Check second cert's there as well, by subject name */
    certInfo.Subject.pbData = subjectName2;
    certInfo.Subject.cbData = sizeof(subjectName2);
    context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
     CERT_FIND_SUBJECT_NAME, &certInfo.Subject, NULL);
    ok(context != NULL, "CertFindCertificateInStore failed: %08x\n",
     GetLastError());
    if (context)
    {
        context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
         CERT_FIND_SUBJECT_NAME, &certInfo.Subject, context);
        ok(context == NULL, "Expected one cert only\n");
    }

    /* Strange but true: searching for the subject cert requires you to set
     * the issuer, not the subject
     */
    context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
     CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
    ok(context == NULL, "Expected no certificate\n");
    certInfo.Subject.pbData = NULL;
    certInfo.Subject.cbData = 0;
    certInfo.Issuer.pbData = subjectName2;
    certInfo.Issuer.cbData = sizeof(subjectName2);
    context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
     CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
    ok(context != NULL, "CertFindCertificateInStore failed: %08x\n",
     GetLastError());
    if (context)
    {
        context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
         CERT_FIND_SUBJECT_CERT, &certInfo, context);
        ok(context == NULL, "Expected one cert only\n");
    }
    /* A non-matching serial number will not match. */
    certInfo.SerialNumber.pbData = otherSerialNumber;
    certInfo.SerialNumber.cbData = sizeof(otherSerialNumber);
    context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
     CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
    ok(context == NULL, "Expected no match\n");
    /* No serial number will not match */
    certInfo.SerialNumber.cbData = 0;
    context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
     CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
    ok(context == NULL, "Expected no match\n");
    /* A serial number still won't match if the name doesn't */
    certInfo.SerialNumber.pbData = serialNum;
    certInfo.SerialNumber.cbData = sizeof(serialNum);
    certInfo.Issuer.pbData = subjectName3;
    certInfo.Issuer.cbData = sizeof(subjectName3);
    context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
     CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
    ok(context == NULL, "Expected no match\n");

    /* The nice thing about hashes, they're unique */
    blob.pbData = bigCertHash;
    blob.cbData = sizeof(bigCertHash);
    context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
     CERT_FIND_SHA1_HASH, &blob, NULL);
    ok(context != NULL, "CertFindCertificateInStore failed: %08x\n",
     GetLastError());
    if (context)
    {
        context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
         CERT_FIND_SHA1_HASH, &certInfo.Subject, context);
        ok(context == NULL, "Expected one cert only\n");
    }

    /* Searching for NULL string matches any context. */
    count = 0;
    context = NULL;
    do {
        context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
         CERT_FIND_ISSUER_STR, NULL, context);
        if (context)
            count++;
    } while (context);
    ok(count == 3, "expected 3 contexts\n");
    count = 0;
    context = NULL;
    do {
        context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
         CERT_FIND_ISSUER_STR, juan, context);
        if (context)
            count++;
    } while (context);
    ok(count == 2, "expected 2 contexts\n");
    count = 0;
    context = NULL;
    do {
        context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
         CERT_FIND_ISSUER_STR, lang, context);
        if (context)
            count++;
    } while (context);
    ok(count == 3, "expected 3 contexts\n");
    SetLastError(0xdeadbeef);
    context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
     CERT_FIND_ISSUER_STR, malcolm, NULL);
    ok(!context, "expected no certs\n");
    ok(GetLastError() == CRYPT_E_NOT_FOUND,
     "expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());

    CertCloseStore(store, 0);

    /* Another subject cert search, using iTunes's certs */
    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     iTunesCert0, sizeof(iTunesCert0), CERT_STORE_ADD_NEW, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     iTunesCert1, sizeof(iTunesCert1), CERT_STORE_ADD_NEW, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     iTunesCert2, sizeof(iTunesCert2), CERT_STORE_ADD_NEW, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     iTunesCert3, sizeof(iTunesCert3), CERT_STORE_ADD_NEW, &subject);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());

    /* The certInfo's issuer does not match any subject, but the serial
     * number does match a cert whose issuer matches certInfo's issuer.
     * This yields a match.
     */
    certInfo.SerialNumber.cbData = sizeof(iTunesSerialNum);
    certInfo.SerialNumber.pbData = iTunesSerialNum;
    certInfo.Issuer.cbData = sizeof(iTunesIssuer);
    certInfo.Issuer.pbData = iTunesIssuer;
    context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
     CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
    ok(context != NULL, "Expected a match\n");
    if (context)
    {
        ret = CertCompareCertificateName(context->dwCertEncodingType,
         &certInfo.Issuer, &context->pCertInfo->Subject);
        ok(!ret, "Expected subject name not to match\n");
        ret = CertCompareCertificateName(context->dwCertEncodingType,
         &certInfo.Issuer, &context->pCertInfo->Issuer);
        ok(ret, "Expected issuer name to match\n");
        ret = CertCompareIntegerBlob(&certInfo.SerialNumber,
         &context->pCertInfo->SerialNumber);
        ok(ret, "Expected serial number to match\n");
        context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
         CERT_FIND_SUBJECT_CERT, &certInfo, context);
        ok(context == NULL, "Expected one cert only\n");
    }

    context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
     CERT_FIND_ISSUER_OF, subject, NULL);
    ok(context != NULL, "Expected an issuer\n");
    if (context)
    {
        PCCERT_CONTEXT none = CertFindCertificateInStore(store,
         X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_OF, context, NULL);

        ok(!none, "Expected no parent of issuer\n");
        CertFreeCertificateContext(context);
    }
    CertFreeCertificateContext(subject);
    CertCloseStore(store, 0);
}

static void testGetSubjectCert(void)
{
    HCERTSTORE store;
    PCCERT_CONTEXT context1, context2;
    CERT_INFO info = { 0 };
    BOOL ret;

    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(store != NULL, "CertOpenStore failed: %d\n", GetLastError());
    if (!store)
        return;

    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     bigCert, sizeof(bigCert), CERT_STORE_ADD_ALWAYS, NULL);
    ok(ret || broken(GetLastError() == OSS_DATA_ERROR /* win98 */),
     "CertAddEncodedCertificateToStore failed: %08x\n", GetLastError());
    if (!ret && GetLastError() == OSS_DATA_ERROR)
    {
        skip("bigCert can't be decoded, skipping tests\n");
        return;
    }
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     bigCert2, sizeof(bigCert2), CERT_STORE_ADD_NEW, &context1);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());
    ok(context1 != NULL, "Expected a context\n");
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     certWithUsage, sizeof(certWithUsage), CERT_STORE_ADD_NEW, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());

    context2 = CertGetSubjectCertificateFromStore(store, X509_ASN_ENCODING,
     NULL);
    ok(!context2 && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());
    context2 = CertGetSubjectCertificateFromStore(store, X509_ASN_ENCODING,
     &info);
    ok(!context2 && GetLastError() == CRYPT_E_NOT_FOUND,
     "Expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());
    info.SerialNumber.cbData = sizeof(serialNum);
    info.SerialNumber.pbData = serialNum;
    context2 = CertGetSubjectCertificateFromStore(store, X509_ASN_ENCODING,
     &info);
    ok(!context2 && GetLastError() == CRYPT_E_NOT_FOUND,
     "Expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());
    info.Issuer.cbData = sizeof(subjectName2);
    info.Issuer.pbData = subjectName2;
    context2 = CertGetSubjectCertificateFromStore(store, X509_ASN_ENCODING,
     &info);
    ok(context2 != NULL,
     "CertGetSubjectCertificateFromStore failed: %08x\n", GetLastError());
    /* Not only should this find a context, but it should be the same
     * (same address) as context1.
     */
    ok(context1 == context2, "Expected identical context addresses\n");
    CertFreeCertificateContext(context2);

    CertFreeCertificateContext(context1);
    CertCloseStore(store, 0);
}

/* This expires in 1970 or so */
static const BYTE expiredCert[] = { 0x30, 0x82, 0x01, 0x33, 0x30, 0x81, 0xe2,
 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0xc4, 0xd7, 0x7f, 0x0e, 0x6f, 0xa6,
 0x8c, 0xaa, 0x47, 0x47, 0x40, 0xe7, 0xb7, 0x0b, 0x4a, 0x7f, 0x30, 0x09, 0x06,
 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1d, 0x05, 0x00, 0x30, 0x1f, 0x31, 0x1d, 0x30,
 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x14, 0x61, 0x72, 0x69, 0x63, 0x40,
 0x63, 0x6f, 0x64, 0x65, 0x77, 0x65, 0x61, 0x76, 0x65, 0x72, 0x73, 0x2e, 0x63,
 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x36, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30,
 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x37, 0x30, 0x30, 0x31, 0x30,
 0x31, 0x30, 0x36, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30,
 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x14, 0x61, 0x72, 0x69, 0x63, 0x40,
 0x63, 0x6f, 0x64, 0x65, 0x77, 0x65, 0x61, 0x76, 0x65, 0x72, 0x73, 0x2e, 0x63,
 0x6f, 0x6d, 0x30, 0x5c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x4b, 0x00, 0x30, 0x48, 0x02, 0x41,
 0x00, 0xa1, 0xaf, 0x4a, 0xea, 0xa7, 0x83, 0x57, 0xc0, 0x37, 0x33, 0x7e, 0x29,
 0x5e, 0x0d, 0xfc, 0x44, 0x74, 0x3a, 0x1d, 0xc3, 0x1b, 0x1d, 0x96, 0xed, 0x4e,
 0xf4, 0x1b, 0x98, 0xec, 0x69, 0x1b, 0x04, 0xea, 0x25, 0xcf, 0xb3, 0x2a, 0xf5,
 0xd9, 0x22, 0xd9, 0x8d, 0x08, 0x39, 0x81, 0xc6, 0xe0, 0x4f, 0x12, 0x37, 0x2a,
 0x3f, 0x80, 0xa6, 0x6c, 0x67, 0x43, 0x3a, 0xdd, 0x95, 0x0c, 0xbb, 0x2f, 0x6b,
 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
 0x1d, 0x05, 0x00, 0x03, 0x41, 0x00, 0x8f, 0xa2, 0x5b, 0xd6, 0xdf, 0x34, 0xd0,
 0xa2, 0xa7, 0x47, 0xf1, 0x13, 0x79, 0xd3, 0xf3, 0x39, 0xbd, 0x4e, 0x2b, 0xa3,
 0xf4, 0x63, 0x37, 0xac, 0x5a, 0x0c, 0x5e, 0x4d, 0x0d, 0x54, 0x87, 0x4f, 0x31,
 0xfb, 0xa0, 0xce, 0x8f, 0x9a, 0x2f, 0x4d, 0x48, 0xc6, 0x84, 0x8d, 0xf5, 0x70,
 0x74, 0x17, 0xa5, 0xf3, 0x66, 0x47, 0x06, 0xd6, 0x64, 0x45, 0xbc, 0x52, 0xef,
 0x49, 0xe5, 0xf9, 0x65, 0xf3 };

/* This expires in 2036 or so */
static const BYTE childOfExpired[] = { 0x30, 0x81, 0xcc, 0x30, 0x78, 0xa0,
 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x1f, 0x31, 0x1d,
 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x14, 0x61, 0x72, 0x69, 0x63,
 0x40, 0x63, 0x6f, 0x64, 0x65, 0x77, 0x65, 0x61, 0x76, 0x65, 0x72, 0x73, 0x2e,
 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x30, 0x36, 0x30, 0x35, 0x30, 0x35,
 0x31, 0x37, 0x31, 0x32, 0x34, 0x39, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x35,
 0x30, 0x35, 0x31, 0x37, 0x31, 0x32, 0x34, 0x39, 0x5a, 0x30, 0x15, 0x31, 0x13,
 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x4a, 0x75, 0x61, 0x6e,
 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x00, 0x30, 0x07, 0x30, 0x02, 0x06, 0x00, 0x03,
 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
 0x01, 0x05, 0x05, 0x00, 0x03, 0x41, 0x00, 0x20, 0x3b, 0xdb, 0x4d, 0x67, 0x50,
 0xec, 0x73, 0x9d, 0xf9, 0x85, 0x5d, 0x18, 0xe9, 0xb4, 0x98, 0xe3, 0x31, 0xb7,
 0x03, 0x0b, 0xc0, 0x39, 0x93, 0x56, 0x81, 0x0a, 0xfc, 0x78, 0xa8, 0x29, 0x42,
 0x5f, 0x69, 0xfb, 0xbc, 0x5b, 0xf2, 0xa6, 0x2a, 0xbe, 0x91, 0x2c, 0xfc, 0x89,
 0x69, 0x15, 0x18, 0x58, 0xe5, 0x02, 0x75, 0xf7, 0x2a, 0xb6, 0xa9, 0xfb, 0x47,
 0x6a, 0x6e, 0x0a, 0x9b, 0xe9, 0xdc };
/* chain10_0 -+
 *            +-> chain7_1
 * chain10_1 -+
 * A chain with two issuers, only one of whose dates is valid.
 */
static const BYTE chain10_0[] = {
0x30,0x82,0x01,0x9b,0x30,0x82,0x01,0x08,0xa0,0x03,0x02,0x01,0x02,0x02,0x10,
0x4a,0x30,0x3a,0x42,0xa2,0x5a,0xb3,0x93,0x4d,0x94,0x06,0xad,0x6d,0x1c,0x34,
0xe6,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1d,0x05,0x00,0x30,0x10,0x31,
0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x03,0x13,0x05,0x43,0x65,0x72,0x74,0x31,
0x30,0x1e,0x17,0x0d,0x30,0x36,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,
0x30,0x5a,0x17,0x0d,0x30,0x36,0x31,0x32,0x33,0x31,0x32,0x33,0x35,0x39,0x35,
0x39,0x5a,0x30,0x10,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x03,0x13,0x05,
0x43,0x65,0x72,0x74,0x31,0x30,0x81,0x9f,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x81,0x8d,0x00,0x30,0x81,0x89,
0x02,0x81,0x81,0x00,0xad,0x7e,0xca,0xf3,0xe5,0x99,0xc2,0x2a,0xca,0x50,0x82,
0x7c,0x2d,0xa4,0x81,0xcd,0x0d,0x0d,0x86,0xd7,0xd8,0xb2,0xde,0xc5,0xc3,0x34,
0x9e,0x07,0x78,0x08,0x11,0x12,0x2d,0x21,0x0a,0x09,0x07,0x14,0x03,0x7a,0xe7,
0x3b,0x58,0xf1,0xde,0x3e,0x01,0x25,0x93,0xab,0x8f,0xce,0x1f,0xc1,0x33,0x91,
0xfe,0x59,0xb9,0x3b,0x9e,0x95,0x12,0x89,0x8e,0xc3,0x4b,0x98,0x1b,0x99,0xc5,
0x07,0xe2,0xdf,0x15,0x4c,0x39,0x76,0x06,0xad,0xdb,0x16,0x06,0x49,0xba,0xcd,
0x0f,0x07,0xd6,0xea,0x27,0xa6,0xfe,0x3d,0x88,0xe5,0x97,0x45,0x72,0xb6,0x1c,
0xc0,0x1c,0xb1,0xa2,0x89,0xe8,0x37,0x9e,0xf6,0x2a,0xcf,0xd5,0x1f,0x2f,0x35,
0x5e,0x8f,0x3a,0x9c,0x61,0xb1,0xf1,0x6c,0xff,0x8c,0xb2,0x2f,0x02,0x03,0x01,
0x00,0x01,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1d,0x05,0x00,0x03,0x81,
0x81,0x00,0x85,0x6e,0x35,0x2f,0x2c,0x51,0x4f,0xd6,0x2a,0xe4,0x9e,0xd0,0x4b,
0xe6,0x90,0xfd,0xf7,0x20,0xad,0x76,0x3f,0x93,0xea,0x7f,0x0d,0x1f,0xb3,0x8e,
0xfd,0xe0,0xe1,0xd6,0xd7,0x9c,0x7d,0x46,0x6b,0x15,0x5c,0xe6,0xc9,0x62,0x3b,
0x70,0x4a,0x4b,0xb2,0x82,0xe3,0x55,0x0c,0xc4,0x90,0x44,0x06,0x6c,0x86,0x1c,
0x6d,0x47,0x12,0xda,0x33,0x95,0x5d,0x98,0x43,0xcb,0x7c,0xfa,0x2b,0xee,0xc4,
0x2d,0xc8,0x95,0x33,0x89,0x08,0x3f,0x9f,0x87,0xea,0x20,0x04,0xaf,0x58,0x4b,
0x9d,0xc0,0x7c,0x0a,0x1b,0x05,0x31,0x3b,0xbb,0x13,0x58,0x2e,0x3f,0x61,0x6b,
0x10,0xb4,0xeb,0xb9,0x1a,0x30,0xfd,0xea,0xca,0x29,0x99,0x5f,0x42,0x2b,0x00,
0xb0,0x08,0xc3,0xf0,0xb6,0xd6,0x6b,0xf9,0x35,0x95 };
static const BYTE chain10_1[] = {
0x30,0x82,0x01,0x9b,0x30,0x82,0x01,0x08,0xa0,0x03,0x02,0x01,0x02,0x02,0x10,
0xbf,0x99,0x4f,0x14,0x03,0x77,0x44,0xb8,0x49,0x02,0x70,0xa1,0xb8,0x9c,0xa7,
0x24,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1d,0x05,0x00,0x30,0x10,0x31,
0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x03,0x13,0x05,0x43,0x65,0x72,0x74,0x31,
0x30,0x1e,0x17,0x0d,0x30,0x37,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,
0x30,0x5a,0x17,0x0d,0x30,0x37,0x31,0x32,0x33,0x31,0x32,0x33,0x35,0x39,0x35,
0x39,0x5a,0x30,0x10,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x03,0x13,0x05,
0x43,0x65,0x72,0x74,0x31,0x30,0x81,0x9f,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x81,0x8d,0x00,0x30,0x81,0x89,
0x02,0x81,0x81,0x00,0xad,0x7e,0xca,0xf3,0xe5,0x99,0xc2,0x2a,0xca,0x50,0x82,
0x7c,0x2d,0xa4,0x81,0xcd,0x0d,0x0d,0x86,0xd7,0xd8,0xb2,0xde,0xc5,0xc3,0x34,
0x9e,0x07,0x78,0x08,0x11,0x12,0x2d,0x21,0x0a,0x09,0x07,0x14,0x03,0x7a,0xe7,
0x3b,0x58,0xf1,0xde,0x3e,0x01,0x25,0x93,0xab,0x8f,0xce,0x1f,0xc1,0x33,0x91,
0xfe,0x59,0xb9,0x3b,0x9e,0x95,0x12,0x89,0x8e,0xc3,0x4b,0x98,0x1b,0x99,0xc5,
0x07,0xe2,0xdf,0x15,0x4c,0x39,0x76,0x06,0xad,0xdb,0x16,0x06,0x49,0xba,0xcd,
0x0f,0x07,0xd6,0xea,0x27,0xa6,0xfe,0x3d,0x88,0xe5,0x97,0x45,0x72,0xb6,0x1c,
0xc0,0x1c,0xb1,0xa2,0x89,0xe8,0x37,0x9e,0xf6,0x2a,0xcf,0xd5,0x1f,0x2f,0x35,
0x5e,0x8f,0x3a,0x9c,0x61,0xb1,0xf1,0x6c,0xff,0x8c,0xb2,0x2f,0x02,0x03,0x01,
0x00,0x01,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1d,0x05,0x00,0x03,0x81,
0x81,0x00,0xa8,0xec,0x8c,0x34,0xe7,0x2c,0xdf,0x75,0x87,0xc4,0xf7,0xda,0x71,
0x72,0x29,0xb2,0x48,0xa8,0x2a,0xec,0x7b,0x7d,0x19,0xb9,0x5f,0x1d,0xd9,0x91,
0x2b,0xc4,0x28,0x7e,0xd6,0xb5,0x91,0x69,0xa5,0x8a,0x1a,0x1f,0x97,0x98,0x46,
0x9d,0xdf,0x12,0xf6,0x45,0x62,0xad,0x60,0xb6,0xba,0xb0,0xfd,0xf5,0x9f,0xc6,
0x98,0x05,0x4f,0x4d,0x48,0xdc,0xee,0x69,0xbe,0xb8,0xc4,0xc4,0xd7,0x1b,0xb1,
0x1f,0x64,0xd6,0x45,0xa7,0xdb,0xb3,0x87,0x63,0x0f,0x54,0xe1,0x3a,0x6b,0x57,
0x36,0xd7,0x68,0x65,0xcf,0xda,0x57,0x8d,0xcd,0x84,0x75,0x47,0x26,0x2c,0xef,
0x1e,0x8f,0xc7,0x3b,0xee,0x5d,0x03,0xa6,0xdf,0x3a,0x20,0xb2,0xcc,0xc9,0x09,
0x2c,0xfe,0x2b,0x79,0xb0,0xca,0x2c,0x9a,0x81,0x6b };
static const BYTE chain7_1[] = {
0x30,0x82,0x01,0x93,0x30,0x81,0xfd,0xa0,0x03,0x02,0x01,0x02,0x02,0x01,0x01,
0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,0x00,
0x30,0x10,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x03,0x13,0x05,0x43,0x65,
0x72,0x74,0x31,0x30,0x1e,0x17,0x0d,0x30,0x37,0x30,0x31,0x30,0x31,0x30,0x30,
0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,0x30,0x37,0x31,0x32,0x33,0x31,0x32,0x33,
0x35,0x39,0x35,0x39,0x5a,0x30,0x10,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,
0x03,0x13,0x05,0x43,0x65,0x72,0x74,0x32,0x30,0x81,0x9f,0x30,0x0d,0x06,0x09,
0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x81,0x8d,0x00,
0x30,0x81,0x89,0x02,0x81,0x81,0x00,0xb8,0x52,0xda,0xc5,0x4b,0x3f,0xe5,0x33,
0x0e,0x67,0x5f,0x48,0x21,0xdc,0x7e,0xef,0x37,0x33,0xba,0xff,0xb4,0xc6,0xdc,
0xb6,0x17,0x8e,0x20,0x55,0x07,0x12,0xd2,0x7b,0x3c,0xce,0x30,0xc5,0xa7,0x48,
0x9f,0x6e,0xfe,0xb8,0xbe,0xdb,0x9f,0x9b,0x17,0x60,0x16,0xde,0xc6,0x8b,0x47,
0xd1,0x57,0x71,0x3c,0x93,0xfc,0xbd,0xec,0x44,0x32,0x3b,0xb9,0xcf,0x6b,0x05,
0x72,0xa7,0x87,0x8e,0x7e,0xd4,0x9a,0x87,0x1c,0x2f,0xb7,0x82,0x40,0xfc,0x6a,
0x80,0x83,0x68,0x28,0xce,0x84,0xf4,0x0b,0x2e,0x44,0xcb,0x53,0xac,0x85,0x85,
0xb5,0x46,0x36,0x98,0x3c,0x10,0x02,0xaa,0x02,0xbc,0x8b,0xa2,0x23,0xb2,0xd3,
0x51,0x9a,0x22,0x4a,0xe3,0xaa,0x4e,0x7c,0xda,0x38,0xcf,0x49,0x98,0x72,0xa3,
0x02,0x03,0x01,0x00,0x01,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x01,0x01,0x05,0x05,0x00,0x03,0x81,0x81,0x00,0x9f,0x69,0xfd,0x26,0xd5,0x4b,
0xe0,0xab,0x12,0x21,0xb9,0xfc,0xf7,0xe0,0x0c,0x09,0x94,0xad,0x27,0xd7,0x9d,
0xa3,0xcc,0x46,0x2a,0x25,0x9a,0x24,0xa7,0x31,0x58,0x78,0xf5,0xfc,0x30,0xe1,
0x6d,0xfd,0x59,0xab,0xbe,0x69,0xa0,0xea,0xe3,0x7d,0x7a,0x7b,0xe5,0x85,0xeb,
0x86,0x6a,0x84,0x3c,0x96,0x01,0x1a,0x70,0xa7,0xb8,0xcb,0xf2,0x11,0xe7,0x52,
0x9c,0x58,0x2d,0xac,0x63,0xce,0x72,0x4b,0xad,0x62,0xa8,0x1d,0x75,0x96,0xe2,
0x27,0xf5,0x6f,0xba,0x91,0xf8,0xf1,0xb0,0xbf,0x90,0x24,0x6d,0xba,0x5d,0xd7,
0x39,0x63,0x3b,0x7c,0x04,0x5d,0x89,0x9d,0x1c,0xf2,0xf7,0xcc,0xdf,0x6e,0x8a,
0x43,0xa9,0xdd,0x86,0x05,0xa2,0xf3,0x22,0x2d,0x1e,0x70,0xa1,0x59,0xd7,0xa5,
0x94,0x7d };

static void testGetIssuerCert(void)
{
    BOOL ret;
    PCCERT_CONTEXT parent, child, cert1, cert2, cert3;
    DWORD flags = 0xffffffff, size;
    CERT_NAME_BLOB certsubject;
    BYTE *certencoded;
    WCHAR rootW[] = {'R', 'O', 'O', 'T', '\0'},
          certname[] = {'C', 'N', '=', 'd', 'u', 'm', 'm', 'y', ',', ' ', 'T', '=', 'T', 'e', 's', 't', '\0'};
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);

    ok(store != NULL, "CertOpenStore failed: %08x\n", GetLastError());

    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     expiredCert, sizeof(expiredCert), CERT_STORE_ADD_ALWAYS, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());

    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     childOfExpired, sizeof(childOfExpired), CERT_STORE_ADD_ALWAYS, &child);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n",
     GetLastError());

    /* These crash:
    parent = CertGetIssuerCertificateFromStore(NULL, NULL, NULL, NULL);
    parent = CertGetIssuerCertificateFromStore(store, NULL, NULL, NULL);
     */
    parent = CertGetIssuerCertificateFromStore(NULL, NULL, NULL, &flags);
    ok(!parent && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());
    parent = CertGetIssuerCertificateFromStore(store, NULL, NULL, &flags);
    ok(!parent && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());
    parent = CertGetIssuerCertificateFromStore(store, child, NULL, &flags);
    ok(!parent && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());
    /* Confusing: the caller cannot set either of the
     * CERT_STORE_NO_*_FLAGs, as these are not checks,
     * they're results:
     */
    flags = CERT_STORE_NO_CRL_FLAG | CERT_STORE_NO_ISSUER_FLAG;
    parent = CertGetIssuerCertificateFromStore(store, child, NULL, &flags);
    ok(!parent && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());
    /* Perform no checks */
    flags = 0;
    parent = CertGetIssuerCertificateFromStore(store, child, NULL, &flags);
    ok(parent != NULL, "CertGetIssuerCertificateFromStore failed: %08x\n",
     GetLastError());
    if (parent)
        CertFreeCertificateContext(parent);
    /* Check revocation and signature only */
    flags = CERT_STORE_REVOCATION_FLAG | CERT_STORE_SIGNATURE_FLAG;
    parent = CertGetIssuerCertificateFromStore(store, child, NULL, &flags);
    ok(parent != NULL, "CertGetIssuerCertificateFromStore failed: %08x\n",
     GetLastError());
    /* Confusing: CERT_STORE_REVOCATION_FLAG succeeds when there is no CRL by
     * setting CERT_STORE_NO_CRL_FLAG.
     */
    ok(flags == (CERT_STORE_REVOCATION_FLAG | CERT_STORE_NO_CRL_FLAG),
     "Expected CERT_STORE_REVOCATION_FLAG | CERT_STORE_NO_CRL_FLAG, got %08x\n",
     flags);
    if (parent)
        CertFreeCertificateContext(parent);
    /* Checking time validity is not productive, because while most Windows
     * versions return 0 (time valid) because the child is not expired,
     * Windows 2003 SP1 returns that it is expired.  Thus the range of
     * possibilities is covered, and a test verifies nothing.
     */

    CertFreeCertificateContext(child);
    CertCloseStore(store, 0);

    flags = 0;
    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    /* With only the child certificate, no issuer will be found */
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     chain7_1, sizeof(chain7_1), CERT_STORE_ADD_ALWAYS, &child);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n", GetLastError());
    parent = CertGetIssuerCertificateFromStore(store, child, NULL, &flags);
    ok(parent == NULL, "Expected no issuer\n");
    ok(GetLastError() == CRYPT_E_NOT_FOUND, "Expected CRYPT_E_NOT_FOUND, got %08X\n", GetLastError());
    /* Adding an issuer allows one (and only one) issuer to be found */
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     chain10_1, sizeof(chain10_1), CERT_STORE_ADD_ALWAYS, &cert1);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n", GetLastError());
    parent = CertGetIssuerCertificateFromStore(store, child, NULL, &flags);
    ok(parent == cert1, "Expected cert1 to be the issuer\n");
    parent = CertGetIssuerCertificateFromStore(store, child, parent, &flags);
    ok(parent == NULL, "Expected only one issuer\n");
    ok(GetLastError() == CRYPT_E_NOT_FOUND, "Expected CRYPT_E_NOT_FOUND, got %08X\n", GetLastError());
    /* Adding a second issuer allows two issuers to be found - and the second
     * issuer is found before the first, implying certs are added to the head
     * of a list.
     */
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     chain10_0, sizeof(chain10_0), CERT_STORE_ADD_ALWAYS, &cert2);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n", GetLastError());
    parent = CertGetIssuerCertificateFromStore(store, child, NULL, &flags);
    ok(parent == cert2, "Expected cert2 to be the first issuer\n");
    parent = CertGetIssuerCertificateFromStore(store, child, parent, &flags);
    ok(parent == cert1, "Expected cert1 to be the second issuer\n");
    parent = CertGetIssuerCertificateFromStore(store, child, parent, &flags);
    ok(parent == NULL, "Expected no more than two issuers\n");
    ok(GetLastError() == CRYPT_E_NOT_FOUND, "Expected CRYPT_E_NOT_FOUND, got %08X\n", GetLastError());
    CertFreeCertificateContext(child);
    CertFreeCertificateContext(cert1);
    CertFreeCertificateContext(cert2);
    CertCloseStore(store, 0);

    /* Repeat the test, reversing the order in which issuers are added,
     * to show it's order-dependent.
     */
    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    /* With only the child certificate, no issuer will be found */
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     chain7_1, sizeof(chain7_1), CERT_STORE_ADD_ALWAYS, &child);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n", GetLastError());
    parent = CertGetIssuerCertificateFromStore(store, child, NULL, &flags);
    ok(parent == NULL, "Expected no issuer\n");
    ok(GetLastError() == CRYPT_E_NOT_FOUND, "Expected CRYPT_E_NOT_FOUND, got %08X\n", GetLastError());
    /* Adding an issuer allows one (and only one) issuer to be found */
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     chain10_0, sizeof(chain10_0), CERT_STORE_ADD_ALWAYS, &cert1);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n", GetLastError());
    parent = CertGetIssuerCertificateFromStore(store, child, NULL, &flags);
    ok(parent == cert1, "Expected cert1 to be the issuer\n");
    parent = CertGetIssuerCertificateFromStore(store, child, parent, &flags);
    ok(parent == NULL, "Expected only one issuer\n");
    ok(GetLastError() == CRYPT_E_NOT_FOUND, "Expected CRYPT_E_NOT_FOUND, got %08X\n", GetLastError());
    /* Adding a second issuer allows two issuers to be found - and the second
     * issuer is found before the first, implying certs are added to the head
     * of a list.
     */
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     chain10_1, sizeof(chain10_1), CERT_STORE_ADD_ALWAYS, &cert2);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n", GetLastError());
    parent = CertGetIssuerCertificateFromStore(store, child, NULL, &flags);
    ok(parent == cert2, "Expected cert2 to be the first issuer\n");
    parent = CertGetIssuerCertificateFromStore(store, child, parent, &flags);
    ok(parent == cert1, "Expected cert1 to be the second issuer\n");
    parent = CertGetIssuerCertificateFromStore(store, child, parent, &flags);
    ok(parent == NULL, "Expected no more than two issuers\n");
    ok(GetLastError() == CRYPT_E_NOT_FOUND, "Expected CRYPT_E_NOT_FOUND, got %08X\n", GetLastError());

    /* Self-sign a certificate, add to the store and test getting the issuer */
    size = 0;
    ok(CertStrToNameW(X509_ASN_ENCODING, certname, CERT_X500_NAME_STR, NULL, NULL, &size, NULL),
       "CertStrToName should have worked\n");
    certencoded = HeapAlloc(GetProcessHeap(), 0, size);
    ok(CertStrToNameW(X509_ASN_ENCODING, certname, CERT_X500_NAME_STR, NULL, certencoded, &size, NULL),
       "CertStrToName should have worked\n");
    certsubject.pbData = certencoded;
    certsubject.cbData = size;
    cert3 = CertCreateSelfSignCertificate(0, &certsubject, 0, NULL, NULL, NULL, NULL, NULL);
    ok(cert3 != NULL, "CertCreateSelfSignCertificate should have worked\n");
    ret = CertAddCertificateContextToStore(store, cert3, CERT_STORE_ADD_REPLACE_EXISTING, 0);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08x\n", GetLastError());
    CertFreeCertificateContext(cert3);
    cert3 = CertEnumCertificatesInStore(store, NULL);
    ok(cert3 != NULL, "CertEnumCertificatesInStore should have worked\n");
    SetLastError(0xdeadbeef);
    flags = 0;
    parent = CertGetIssuerCertificateFromStore(store, cert3, NULL, &flags);
    ok(!parent, "Expected NULL\n");
    ok(GetLastError() == CRYPT_E_SELF_SIGNED,
       "Expected CRYPT_E_SELF_SIGNED, got %08X\n", GetLastError());
    CertFreeCertificateContext(child);
    CertFreeCertificateContext(cert1);
    CertFreeCertificateContext(cert2);
    CertFreeCertificateContext(cert3);
    CertCloseStore(store, 0);
    HeapFree(GetProcessHeap(), 0, certencoded);

    /* Test root storage self-signed certificate */
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, rootW);
    ok(store != NULL, "CertOpenStore failed: %08x\n", GetLastError());
    flags = 0;
    cert1 = CertEnumCertificatesInStore(store, NULL);
    ok(cert1 != NULL, "CertEnumCertificatesInStore should have worked\n");
    SetLastError(0xdeadbeef);
    parent = CertGetIssuerCertificateFromStore(store, cert1, NULL, &flags);
    ok(!parent, "Expected NULL\n");
    ok(GetLastError() == CRYPT_E_SELF_SIGNED,
       "Expected CRYPT_E_SELF_SIGNED, got %08X\n", GetLastError());
    CertFreeCertificateContext(cert1);
    CertCloseStore(store, 0);
}

static void testCryptHashCert(void)
{
    static const BYTE emptyHash[] = { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b,
     0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07,
     0x09 };
    static const BYTE knownHash[] = { 0xae, 0x9d, 0xbf, 0x6d, 0xf5, 0x46, 0xee,
     0x8b, 0xc5, 0x7a, 0x13, 0xba, 0xc2, 0xb1, 0x04, 0xf2, 0xbf, 0x52, 0xa8,
     0xa2 };
    static const BYTE toHash[] = "abcdefghijklmnopqrstuvwxyz0123456789.,;!?:";
    BOOL ret;
    BYTE hash[20];
    DWORD hashLen = sizeof(hash);

    /* NULL buffer and nonzero length crashes
    ret = CryptHashCertificate(0, 0, 0, NULL, size, hash, &hashLen);
       empty hash length also crashes
    ret = CryptHashCertificate(0, 0, 0, buf, size, hash, NULL);
     */
    /* Test empty hash */
    ret = CryptHashCertificate(0, 0, 0, toHash, sizeof(toHash), NULL,
     &hashLen);
    ok(ret, "CryptHashCertificate failed: %08x\n", GetLastError());
    ok(hashLen == sizeof(hash), "Got unexpected size of hash %d\n", hashLen);
    /* Test with empty buffer */
    ret = CryptHashCertificate(0, 0, 0, NULL, 0, hash, &hashLen);
    ok(ret, "CryptHashCertificate failed: %08x\n", GetLastError());
    ok(!memcmp(hash, emptyHash, sizeof(emptyHash)),
     "Unexpected hash of nothing\n");
    /* Test a known value */
    ret = CryptHashCertificate(0, 0, 0, toHash, sizeof(toHash), hash,
     &hashLen);
    ok(ret, "CryptHashCertificate failed: %08x\n", GetLastError());
    ok(!memcmp(hash, knownHash, sizeof(knownHash)), "Unexpected hash\n");
}

static void testCryptHashCert2(void)
{
    static const BYTE emptyHash[] = { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b,
     0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07,
     0x09 };
    static const BYTE knownHash[] = { 0xae, 0x9d, 0xbf, 0x6d, 0xf5, 0x46, 0xee,
     0x8b, 0xc5, 0x7a, 0x13, 0xba, 0xc2, 0xb1, 0x04, 0xf2, 0xbf, 0x52, 0xa8,
     0xa2 };
    static const BYTE toHash[] = "abcdefghijklmnopqrstuvwxyz0123456789.,;!?:";
    BOOL ret;
    BYTE hash[20];
    DWORD hashLen;
    const WCHAR SHA1[] = { 'S', 'H', 'A', '1', '\0' };
    const WCHAR invalidAlgorithm[] = { '_', 'S', 'H', 'O', 'U', 'L', 'D',
                                       'N', 'O', 'T',
                                       'E', 'X', 'I', 'S', 'T', '_', '\0' };

    if (!pCryptHashCertificate2)
    {
        win_skip("CryptHashCertificate2() is not available\n");
        return;
    }

    /* Test empty hash */
    hashLen = sizeof(hash);
    ret = pCryptHashCertificate2(SHA1, 0, NULL, NULL, 0, hash, &hashLen);
    ok(ret, "CryptHashCertificate2 failed: %08x\n", GetLastError());
    ok(hashLen == sizeof(hash), "Got unexpected size of hash %d\n", hashLen);
    ok(!memcmp(hash, emptyHash, sizeof(emptyHash)), "Unexpected hash of nothing\n");

    /* Test known hash */
    hashLen = sizeof(hash);
    ret = pCryptHashCertificate2(SHA1, 0, NULL, toHash, sizeof(toHash), hash, &hashLen);
    ok(ret, "CryptHashCertificate2 failed: %08x\n", GetLastError());
    ok(hashLen == sizeof(hash), "Got unexpected size of hash %d\n", hashLen);
    ok(!memcmp(hash, knownHash, sizeof(knownHash)), "Unexpected hash\n");

    /* Test null hash size pointer just sets hash size */
    hashLen = 0;
    ret = pCryptHashCertificate2(SHA1, 0, NULL, toHash, sizeof(toHash), NULL, &hashLen);
    ok(ret, "CryptHashCertificate2 failed: %08x\n", GetLastError());
    ok(hashLen == sizeof(hash), "Hash size not set correctly (%d)\n", hashLen);

    /* Null algorithm ID crashes Windows implementations */
    if (0) {
        /* Test null algorithm ID */
        hashLen = sizeof(hash);
        ret = pCryptHashCertificate2(NULL, 0, NULL, toHash, sizeof(toHash), hash, &hashLen);
    }

    /* Test invalid algorithm */
    hashLen = sizeof(hash);
    SetLastError(0xdeadbeef);
    ret = pCryptHashCertificate2(invalidAlgorithm, 0, NULL, toHash, sizeof(toHash), hash, &hashLen);
    ok(!ret && GetLastError() == STATUS_NOT_FOUND,
     "Expected STATUS_NOT_FOUND (0x%08x), got 0x%08x\n", STATUS_NOT_FOUND, GetLastError());

    /* Test hash buffer too small */
    hashLen = sizeof(hash) / 2;
    SetLastError(0xdeadbeef);
    ret = pCryptHashCertificate2(SHA1, 0, NULL, toHash, sizeof(toHash), hash, &hashLen);
    ok(!ret && GetLastError() == ERROR_MORE_DATA,
     "Expected ERROR_MORE_DATA (%d), got %d\n", ERROR_MORE_DATA, GetLastError());

    /* Null hash length crashes Windows implementations */
    if (0) {
        /* Test hashLen null with hash */
        ret = pCryptHashCertificate2(SHA1, 0, NULL, toHash, sizeof(toHash), hash, NULL);

        /* Test hashLen null with no hash */
        ret = pCryptHashCertificate2(SHA1, 0, NULL, toHash, sizeof(toHash), NULL, NULL);
    }
}

static void verifySig(HCRYPTPROV csp, const BYTE *toSign, size_t toSignLen,
 const BYTE *sig, unsigned int sigLen)
{
    HCRYPTHASH hash;
    BOOL ret = CryptCreateHash(csp, CALG_SHA1, 0, 0, &hash);

    ok(ret, "CryptCreateHash failed: %08x\n", GetLastError());
    if (ret)
    {
        BYTE mySig[64];
        DWORD mySigSize = sizeof(mySig);

        ret = CryptHashData(hash, toSign, toSignLen, 0);
        ok(ret, "CryptHashData failed: %08x\n", GetLastError());
        /* use the A variant so the test can run on Win9x */
        ret = CryptSignHashA(hash, AT_SIGNATURE, NULL, 0, mySig, &mySigSize);
        ok(ret, "CryptSignHash failed: %08x\n", GetLastError());
        if (ret)
        {
            ok(mySigSize == sigLen, "Expected sig length %d, got %d\n",
             sigLen, mySigSize);
            ok(!memcmp(mySig, sig, sigLen), "Unexpected signature\n");
        }
        CryptDestroyHash(hash);
    }
}

/* Tests signing the certificate described by toBeSigned with the CSP passed in,
 * using the algorithm with OID sigOID.  The CSP is assumed to be empty, and a
 * keyset named AT_SIGNATURE will be added to it.  The signature will be stored
 * in sig.  sigLen should be at least 64 bytes.
 */
static void testSignCert(HCRYPTPROV csp, const CRYPT_DATA_BLOB *toBeSigned,
 LPCSTR sigOID, BYTE *sig, DWORD *sigLen)
{
    BOOL ret;
    DWORD size = 0;
    CRYPT_ALGORITHM_IDENTIFIER algoID = { NULL, { 0, NULL } };
    HCRYPTKEY key;

    /* These all crash
    ret = CryptSignCertificate(0, 0, 0, NULL, 0, NULL, NULL, NULL, NULL);
    ret = CryptSignCertificate(0, 0, 0, NULL, 0, NULL, NULL, NULL, &size);
    ret = CryptSignCertificate(0, 0, 0, toBeSigned->pbData, toBeSigned->cbData,
     NULL, NULL, NULL, &size);
     */
    ret = CryptSignCertificate(0, 0, 0, toBeSigned->pbData, toBeSigned->cbData,
     &algoID, NULL, NULL, &size);
    ok(!ret && GetLastError() == NTE_BAD_ALGID, 
     "Expected NTE_BAD_ALGID, got %08x\n", GetLastError());
    algoID.pszObjId = (LPSTR)sigOID;
    ret = CryptSignCertificate(0, 0, 0, toBeSigned->pbData, toBeSigned->cbData,
     &algoID, NULL, NULL, &size);
    ok(!ret &&
     (GetLastError() == ERROR_INVALID_PARAMETER || GetLastError() == NTE_BAD_ALGID),
     "Expected ERROR_INVALID_PARAMETER or NTE_BAD_ALGID, got %08x\n",
     GetLastError());
    ret = CryptSignCertificate(0, AT_SIGNATURE, 0, toBeSigned->pbData,
     toBeSigned->cbData, &algoID, NULL, NULL, &size);
    ok(!ret &&
     (GetLastError() == ERROR_INVALID_PARAMETER || GetLastError() == NTE_BAD_ALGID),
     "Expected ERROR_INVALID_PARAMETER or NTE_BAD_ALGID, got %08x\n",
     GetLastError());

    /* No keys exist in the new CSP yet.. */
    ret = CryptSignCertificate(csp, AT_SIGNATURE, 0, toBeSigned->pbData,
     toBeSigned->cbData, &algoID, NULL, NULL, &size);
    ok(!ret && (GetLastError() == NTE_BAD_KEYSET || GetLastError() ==
     NTE_NO_KEY), "Expected NTE_BAD_KEYSET or NTE_NO_KEY, got %08x\n",
     GetLastError());
    ret = CryptGenKey(csp, AT_SIGNATURE, 0, &key);
    ok(ret, "CryptGenKey failed: %08x\n", GetLastError());
    if (ret)
    {
        ret = CryptSignCertificate(csp, AT_SIGNATURE, 0, toBeSigned->pbData,
         toBeSigned->cbData, &algoID, NULL, NULL, &size);
        ok(ret, "CryptSignCertificate failed: %08x\n", GetLastError());
        ok(size <= *sigLen, "Expected size <= %d, got %d\n", *sigLen, size);
        if (ret)
        {
            ret = CryptSignCertificate(csp, AT_SIGNATURE, 0, toBeSigned->pbData,
             toBeSigned->cbData, &algoID, NULL, sig, &size);
            ok(ret, "CryptSignCertificate failed: %08x\n", GetLastError());
            if (ret)
            {
                *sigLen = size;
                verifySig(csp, toBeSigned->pbData, toBeSigned->cbData, sig,
                 size);
            }
        }
        CryptDestroyKey(key);
    }
}

static void testVerifyCertSig(HCRYPTPROV csp, const CRYPT_DATA_BLOB *toBeSigned,
 LPCSTR sigOID, const BYTE *sig, DWORD sigLen)
{
    CERT_SIGNED_CONTENT_INFO info;
    LPBYTE cert = NULL;
    DWORD size = 0;
    BOOL ret;

    if (!pCryptEncodeObjectEx)
    {
        win_skip("no CryptEncodeObjectEx support\n");
        return;
    }
    ret = CryptVerifyCertificateSignature(0, 0, NULL, 0, NULL);
    ok(!ret && GetLastError() == ERROR_FILE_NOT_FOUND,
     "Expected ERROR_FILE_NOT_FOUND, got %08x\n", GetLastError());
    ret = CryptVerifyCertificateSignature(csp, 0, NULL, 0, NULL);
    ok(!ret && GetLastError() == ERROR_FILE_NOT_FOUND,
     "Expected ERROR_FILE_NOT_FOUND, got %08x\n", GetLastError());
    ret = CryptVerifyCertificateSignature(csp, X509_ASN_ENCODING, NULL, 0,
     NULL);
    ok(!ret && (GetLastError() == CRYPT_E_ASN1_EOD ||
     GetLastError() == OSS_BAD_ARG),
     "Expected CRYPT_E_ASN1_EOD or OSS_BAD_ARG, got %08x\n", GetLastError());
    info.ToBeSigned.cbData = toBeSigned->cbData;
    info.ToBeSigned.pbData = toBeSigned->pbData;
    info.SignatureAlgorithm.pszObjId = (LPSTR)sigOID;
    info.SignatureAlgorithm.Parameters.cbData = 0;
    info.Signature.cbData = sigLen;
    info.Signature.pbData = (BYTE *)sig;
    info.Signature.cUnusedBits = 0;
    ret = pCryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT, &info,
     CRYPT_ENCODE_ALLOC_FLAG, NULL, &cert, &size);
    ok(ret, "CryptEncodeObjectEx failed: %08x\n", GetLastError());
    if (cert)
    {
        PCERT_PUBLIC_KEY_INFO pubKeyInfo = NULL;
        DWORD pubKeySize;

        if (0)
        {
            /* Crashes prior to Vista */
            ret = CryptVerifyCertificateSignature(csp, X509_ASN_ENCODING,
             cert, size, NULL);
        }
        CryptExportPublicKeyInfoEx(csp, AT_SIGNATURE, X509_ASN_ENCODING,
         (LPSTR)sigOID, 0, NULL, NULL, &pubKeySize);
        pubKeyInfo = HeapAlloc(GetProcessHeap(), 0, pubKeySize);
        if (pubKeyInfo)
        {
            ret = CryptExportPublicKeyInfoEx(csp, AT_SIGNATURE,
             X509_ASN_ENCODING, (LPSTR)sigOID, 0, NULL, pubKeyInfo,
             &pubKeySize);
            ok(ret, "CryptExportKey failed: %08x\n", GetLastError());
            if (ret)
            {
                ret = CryptVerifyCertificateSignature(csp, X509_ASN_ENCODING,
                 cert, size, pubKeyInfo);
                ok(ret, "CryptVerifyCertificateSignature failed: %08x\n",
                 GetLastError());
            }
            HeapFree(GetProcessHeap(), 0, pubKeyInfo);
        }
        LocalFree(cert);
    }
}

static void testVerifyCertSigEx(HCRYPTPROV csp, const CRYPT_DATA_BLOB *toBeSigned,
 LPCSTR sigOID, const BYTE *sig, DWORD sigLen)
{
    CERT_SIGNED_CONTENT_INFO info;
    LPBYTE cert = NULL;
    DWORD size = 0;
    BOOL ret;

    if (!pCryptVerifyCertificateSignatureEx)
    {
        win_skip("no CryptVerifyCertificateSignatureEx support\n");
        return;
    }
    if (!pCryptEncodeObjectEx)
    {
        win_skip("no CryptEncodeObjectEx support\n");
        return;
    }
    ret = pCryptVerifyCertificateSignatureEx(0, 0, 0, NULL, 0, NULL, 0, NULL);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());
    ret = pCryptVerifyCertificateSignatureEx(csp, 0, 0, NULL, 0, NULL, 0, NULL);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());
    ret = pCryptVerifyCertificateSignatureEx(csp, X509_ASN_ENCODING, 0, NULL, 0,
     NULL, 0, NULL);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());
    /* This crashes
    ret = pCryptVerifyCertificateSignatureEx(csp, X509_ASN_ENCODING,
     CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, NULL, 0, NULL, 0, NULL);
     */
    info.ToBeSigned.cbData = toBeSigned->cbData;
    info.ToBeSigned.pbData = toBeSigned->pbData;
    info.SignatureAlgorithm.pszObjId = (LPSTR)sigOID;
    info.SignatureAlgorithm.Parameters.cbData = 0;
    info.Signature.cbData = sigLen;
    info.Signature.pbData = (BYTE *)sig;
    info.Signature.cUnusedBits = 0;
    ret = pCryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT, &info,
     CRYPT_ENCODE_ALLOC_FLAG, NULL, &cert, &size);
    ok(ret, "CryptEncodeObjectEx failed: %08x\n", GetLastError());
    if (cert)
    {
        CRYPT_DATA_BLOB certBlob = { 0, NULL };
        PCERT_PUBLIC_KEY_INFO pubKeyInfo = NULL;

        ret = pCryptVerifyCertificateSignatureEx(csp, X509_ASN_ENCODING,
         CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &certBlob, 0, NULL, 0, NULL);
        ok(!ret && GetLastError() == CRYPT_E_ASN1_EOD,
         "Expected CRYPT_E_ASN1_EOD, got %08x\n", GetLastError());
        certBlob.cbData = 1;
        certBlob.pbData = (void *)0xdeadbeef;
        ret = pCryptVerifyCertificateSignatureEx(csp, X509_ASN_ENCODING,
         CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &certBlob, 0, NULL, 0, NULL);
        ok(!ret && (GetLastError() == STATUS_ACCESS_VIOLATION ||
                    GetLastError() == CRYPT_E_ASN1_EOD /* Win9x */ ||
                    GetLastError() == CRYPT_E_ASN1_BADTAG /* Win98 */),
         "Expected STATUS_ACCESS_VIOLATION, CRYPT_E_ASN1_EOD, OR CRYPT_E_ASN1_BADTAG, got %08x\n",
         GetLastError());

        certBlob.cbData = size;
        certBlob.pbData = cert;
        ret = pCryptVerifyCertificateSignatureEx(csp, X509_ASN_ENCODING,
         CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &certBlob, 0, NULL, 0, NULL);
        ok(!ret && GetLastError() == E_INVALIDARG,
         "Expected E_INVALIDARG, got %08x\n", GetLastError());
        ret = pCryptVerifyCertificateSignatureEx(csp, X509_ASN_ENCODING,
         CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &certBlob,
         CRYPT_VERIFY_CERT_SIGN_ISSUER_NULL, NULL, 0, NULL);
        ok(!ret && GetLastError() == E_INVALIDARG,
         "Expected E_INVALIDARG, got %08x\n", GetLastError());
        /* This crashes
        ret = pCryptVerifyCertificateSignatureEx(csp, X509_ASN_ENCODING,
         CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &certBlob,
         CRYPT_VERIFY_CERT_SIGN_ISSUER_PUBKEY, NULL, 0, NULL);
         */
        CryptExportPublicKeyInfoEx(csp, AT_SIGNATURE, X509_ASN_ENCODING,
         (LPSTR)sigOID, 0, NULL, NULL, &size);
        pubKeyInfo = HeapAlloc(GetProcessHeap(), 0, size);
        if (pubKeyInfo)
        {
            ret = CryptExportPublicKeyInfoEx(csp, AT_SIGNATURE,
             X509_ASN_ENCODING, (LPSTR)sigOID, 0, NULL, pubKeyInfo, &size);
            ok(ret, "CryptExportKey failed: %08x\n", GetLastError());
            if (ret)
            {
                ret = pCryptVerifyCertificateSignatureEx(csp, X509_ASN_ENCODING,
                 CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &certBlob,
                 CRYPT_VERIFY_CERT_SIGN_ISSUER_PUBKEY, pubKeyInfo, 0, NULL);
                ok(ret, "CryptVerifyCertificateSignatureEx failed: %08x\n",
                 GetLastError());
            }
            HeapFree(GetProcessHeap(), 0, pubKeyInfo);
        }
        LocalFree(cert);
    }
}

static BYTE emptyCert[] = { 0x30, 0x00 };

static void testCertSigs(void)
{
    HCRYPTPROV csp;
    CRYPT_DATA_BLOB toBeSigned = { sizeof(emptyCert), emptyCert };
    BOOL ret;
    BYTE sig[64];
    DWORD sigSize = sizeof(sig);

    /* Just in case a previous run failed, delete this thing */
    pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_DELETEKEYSET);
    ret = pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_NEWKEYSET);
    ok(ret, "CryptAcquireContext failed: %08x\n", GetLastError());

    testSignCert(csp, &toBeSigned, szOID_RSA_SHA1RSA, sig, &sigSize);
    testVerifyCertSig(csp, &toBeSigned, szOID_RSA_SHA1RSA, sig, sigSize);
    testVerifyCertSigEx(csp, &toBeSigned, szOID_RSA_SHA1RSA, sig, sigSize);

    CryptReleaseContext(csp, 0);
    ret = pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_DELETEKEYSET);
    ok(ret, "CryptAcquireContext failed: %08x\n", GetLastError());
}

static const BYTE md5SignedEmptyCert[] = {
0x30,0x56,0x30,0x33,0x02,0x00,0x30,0x02,0x06,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,
0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,
0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x07,
0x30,0x02,0x06,0x00,0x03,0x01,0x00,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,
0x0d,0x02,0x05,0x05,0x00,0x03,0x11,0x00,0xfb,0x0f,0x66,0x82,0x66,0xd9,0xe5,0xf8,
0xd8,0xa2,0x55,0x2b,0xe1,0xa5,0xd9,0x04 };
static const BYTE md5SignedEmptyCertNoNull[] = {
0x30,0x54,0x30,0x33,0x02,0x00,0x30,0x02,0x06,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,
0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,
0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x07,
0x30,0x02,0x06,0x00,0x03,0x01,0x00,0x30,0x0a,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,
0x0d,0x02,0x05,0x03,0x11,0x00,0x04,0xd9,0xa5,0xe1,0x2b,0x55,0xa2,0xd8,0xf8,0xe5,
0xd9,0x66,0x82,0x66,0x0f,0xfb };

static void testSignAndEncodeCert(void)
{
    static char oid_rsa_md5rsa[] = szOID_RSA_MD5RSA;
    static char oid_rsa_md5[] = szOID_RSA_MD5;
    BOOL ret;
    DWORD size;
    CRYPT_ALGORITHM_IDENTIFIER algID = { 0 };
    CERT_INFO info = { 0 };

    /* Crash
    ret = CryptSignAndEncodeCertificate(0, 0, 0, NULL, NULL, NULL, NULL, NULL,
     NULL);
    ret = CryptSignAndEncodeCertificate(0, 0, 0, NULL, NULL, NULL, NULL, NULL,
     &size);
     */
    ret = CryptSignAndEncodeCertificate(0, 0, 0, NULL, NULL, &algID, NULL, NULL,
     &size);
    ok(!ret && GetLastError() == ERROR_FILE_NOT_FOUND,
     "Expected ERROR_FILE_NOT_FOUND, got %08x\n", GetLastError());
    ret = CryptSignAndEncodeCertificate(0, 0, X509_ASN_ENCODING, NULL, NULL,
     &algID, NULL, NULL, &size);
    ok(!ret && GetLastError() == ERROR_FILE_NOT_FOUND,
     "Expected ERROR_FILE_NOT_FOUND, got %08x\n", GetLastError());
    ret = CryptSignAndEncodeCertificate(0, 0, 0, X509_CERT_TO_BE_SIGNED, NULL,
     &algID, NULL, NULL, &size);
    ok(!ret && GetLastError() == ERROR_FILE_NOT_FOUND,
     "Expected ERROR_FILE_NOT_FOUND, got %08x\n", GetLastError());
    /* Crashes on some win9x boxes */
    if (0)
    {
        ret = CryptSignAndEncodeCertificate(0, 0, X509_ASN_ENCODING,
         X509_CERT_TO_BE_SIGNED, NULL, &algID, NULL, NULL, &size);
        ok(!ret && GetLastError() == STATUS_ACCESS_VIOLATION,
         "Expected STATUS_ACCESS_VIOLATION, got %08x\n", GetLastError());
    }
    /* Crashes
    ret = CryptSignAndEncodeCertificate(0, 0, X509_ASN_ENCODING,
     X509_CERT_TO_BE_SIGNED, &info, NULL, NULL, NULL, &size);
     */
    ret = CryptSignAndEncodeCertificate(0, 0, X509_ASN_ENCODING,
     X509_CERT_TO_BE_SIGNED, &info, &algID, NULL, NULL, &size);
    ok(!ret &&
     (GetLastError() == NTE_BAD_ALGID ||
      GetLastError() == OSS_BAD_PTR), /* win9x */
     "Expected NTE_BAD_ALGID, got %08x\n", GetLastError());
    algID.pszObjId = oid_rsa_md5rsa;
    ret = CryptSignAndEncodeCertificate(0, 0, X509_ASN_ENCODING,
     X509_CERT_TO_BE_SIGNED, &info, &algID, NULL, NULL, &size);
    ok(!ret &&
     (GetLastError() == ERROR_INVALID_PARAMETER ||
      GetLastError() == NTE_BAD_ALGID ||
      GetLastError() == OSS_BAD_PTR), /* Win9x */
     "Expected ERROR_INVALID_PARAMETER or NTE_BAD_ALGID, got %08x\n",
     GetLastError());
    algID.pszObjId = oid_rsa_md5;
    ret = CryptSignAndEncodeCertificate(0, 0, X509_ASN_ENCODING,
     X509_CERT_TO_BE_SIGNED, &info, &algID, NULL, NULL, &size);
    /* oid_rsa_md5 not present in some win2k */
    if (ret)
    {
        LPBYTE buf = HeapAlloc(GetProcessHeap(), 0, size);

        if (buf)
        {
            ret = CryptSignAndEncodeCertificate(0, 0, X509_ASN_ENCODING,
             X509_CERT_TO_BE_SIGNED, &info, &algID, NULL, buf, &size);
            ok(ret, "CryptSignAndEncodeCertificate failed: %08x\n",
             GetLastError());
            /* Tricky: because the NULL parameters may either be omitted or
             * included as an asn.1-encoded NULL (0x05,0x00), two different
             * values are allowed.
             */
            ok(size == sizeof(md5SignedEmptyCert) ||
             size == sizeof(md5SignedEmptyCertNoNull), "Unexpected size %d\n",
             size);
            if (size == sizeof(md5SignedEmptyCert))
                ok(!memcmp(buf, md5SignedEmptyCert, size),
                 "Unexpected value\n");
            else if (size == sizeof(md5SignedEmptyCertNoNull))
                ok(!memcmp(buf, md5SignedEmptyCertNoNull, size),
                 "Unexpected value\n");
            HeapFree(GetProcessHeap(), 0, buf);
        }
    }
}

static void testCreateSelfSignCert(void)
{
    PCCERT_CONTEXT context;
    CERT_NAME_BLOB name = { sizeof(subjectName), subjectName };
    HCRYPTPROV csp;
    BOOL ret;
    HCRYPTKEY key;
    CRYPT_KEY_PROV_INFO info;

    if (!pCertCreateSelfSignCertificate)
    {
        win_skip("CertCreateSelfSignCertificate() is not available\n");
        return;
    }

    /* This crashes:
    context = pCertCreateSelfSignCertificate(0, NULL, 0, NULL, NULL, NULL, NULL,
     NULL);
     * Calling this with no first parameter creates a new key container, which
     * lasts beyond the test, so I don't test that.  Nb: the generated key
     * name is a GUID.
    context = pCertCreateSelfSignCertificate(0, &name, 0, NULL, NULL, NULL, NULL,
     NULL);
     */

    /* Acquire a CSP */
    pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_DELETEKEYSET);
    ret = pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_NEWKEYSET);
    ok(ret, "CryptAcquireContext failed: %08x\n", GetLastError());

    context = pCertCreateSelfSignCertificate(csp, &name, 0, NULL, NULL, NULL,
     NULL, NULL);
    ok(!context && GetLastError() == NTE_NO_KEY,
     "Expected NTE_NO_KEY, got %08x\n", GetLastError());
    ret = CryptGenKey(csp, AT_SIGNATURE, 0, &key);
    ok(ret, "CryptGenKey failed: %08x\n", GetLastError());
    if (ret)
    {
        context = pCertCreateSelfSignCertificate(csp, &name, 0, NULL, NULL, NULL,
         NULL, NULL);
        ok(context != NULL, "CertCreateSelfSignCertificate failed: %08x\n",
         GetLastError());
        if (context)
        {
            DWORD size = 0;

            /* The context must have a key provider info property */
            ret = CertGetCertificateContextProperty(context,
             CERT_KEY_PROV_INFO_PROP_ID, NULL, &size);
            ok(ret && size, "Expected non-zero key provider info\n");
            if (size)
            {
                PCRYPT_KEY_PROV_INFO pInfo = HeapAlloc(GetProcessHeap(), 0, size);

                if (pInfo)
                {
                    ret = CertGetCertificateContextProperty(context,
                     CERT_KEY_PROV_INFO_PROP_ID, pInfo, &size);
                    ok(ret, "CertGetCertificateContextProperty failed: %08x\n",
                     GetLastError());
                    if (ret)
                    {
                        /* Sanity-check the key provider */
                        ok(!lstrcmpW(pInfo->pwszContainerName, cspNameW),
                         "Unexpected key container\n");
                        ok(!lstrcmpW(pInfo->pwszProvName, MS_DEF_PROV_W),
                         "Unexpected provider\n");
                        ok(pInfo->dwKeySpec == AT_SIGNATURE,
                         "Expected AT_SIGNATURE, got %d\n", pInfo->dwKeySpec);
                    }
                    HeapFree(GetProcessHeap(), 0, pInfo);
                }
            }

            CertFreeCertificateContext(context);
        }

        CryptDestroyKey(key);
    }

    CryptReleaseContext(csp, 0);
    ret = pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_DELETEKEYSET);
    ok(ret, "CryptAcquireContext failed: %08x\n", GetLastError());

    /* Do the same test with a CSP, AT_KEYEXCHANGE and key info */
    pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_DELETEKEYSET);
    ret = pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_NEWKEYSET);
    ok(ret, "CryptAcquireContext failed: %08x\n", GetLastError());
    ret = CryptGenKey(csp, AT_SIGNATURE, 0, &key);
    ok(ret, "CryptGenKey failed: %08x\n", GetLastError());

    memset(&info,0,sizeof(info));
    info.dwProvType = PROV_RSA_FULL;
    info.dwKeySpec = AT_KEYEXCHANGE;
    info.pwszProvName = (LPWSTR) MS_DEF_PROV_W;
    info.pwszContainerName = cspNameW;
    /* This should fail because the CSP doesn't have the specified key. */
    SetLastError(0xdeadbeef);
    context = pCertCreateSelfSignCertificate(csp, &name, 0, &info, NULL, NULL,
        NULL, NULL);
    ok(context == NULL, "expected failure\n");
    if (context != NULL)
        CertFreeCertificateContext(context);
    else
        ok(GetLastError() == NTE_NO_KEY, "expected NTE_NO_KEY, got %08x\n",
            GetLastError());
    /* Again, with a CSP, AT_SIGNATURE and key info */
    info.dwKeySpec = AT_SIGNATURE;
    SetLastError(0xdeadbeef);
    context = pCertCreateSelfSignCertificate(csp, &name, 0, &info, NULL, NULL,
        NULL, NULL);
    ok(context != NULL,
        "CertCreateSelfSignCertificate failed: %08x\n", GetLastError());
    if (context)
    {
        DWORD size = 0;

        /* The context must have a key provider info property */
        ret = CertGetCertificateContextProperty(context,
            CERT_KEY_PROV_INFO_PROP_ID, NULL, &size);
        ok(ret && size, "Expected non-zero key provider info\n");
        if (size)
        {
            PCRYPT_KEY_PROV_INFO pInfo = HeapAlloc(GetProcessHeap(), 0, size);

            if (pInfo)
            {
                ret = CertGetCertificateContextProperty(context,
                    CERT_KEY_PROV_INFO_PROP_ID, pInfo, &size);
                ok(ret, "CertGetCertificateContextProperty failed: %08x\n",
                    GetLastError());
                if (ret)
                {
                    /* Sanity-check the key provider */
                    ok(!lstrcmpW(pInfo->pwszContainerName, cspNameW),
                        "Unexpected key container\n");
                    ok(!lstrcmpW(pInfo->pwszProvName, MS_DEF_PROV_W),
                        "Unexpected provider\n");
                    ok(pInfo->dwKeySpec == AT_SIGNATURE,
                        "Expected AT_SIGNATURE, got %d\n", pInfo->dwKeySpec);
                }
                HeapFree(GetProcessHeap(), 0, pInfo);
            }
        }

        CertFreeCertificateContext(context);
    }
    CryptDestroyKey(key);

    CryptReleaseContext(csp, 0);
    ret = pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_DELETEKEYSET);
    ok(ret, "CryptAcquireContext failed: %08x\n", GetLastError());

    /* Do the same test with no CSP, AT_KEYEXCHANGE and key info */
    info.dwKeySpec = AT_KEYEXCHANGE;
    context = pCertCreateSelfSignCertificate(0, &name, 0, &info, NULL, NULL,
        NULL, NULL);
    ok(context != NULL, "CertCreateSelfSignCertificate failed: %08x\n",
        GetLastError());
    if (context)
    {
        DWORD size = 0;

        /* The context must have a key provider info property */
        ret = CertGetCertificateContextProperty(context,
            CERT_KEY_PROV_INFO_PROP_ID, NULL, &size);
        ok(ret && size, "Expected non-zero key provider info\n");
        if (size)
        {
            PCRYPT_KEY_PROV_INFO pInfo = HeapAlloc(GetProcessHeap(), 0, size);

            if (pInfo)
            {
                ret = CertGetCertificateContextProperty(context,
                    CERT_KEY_PROV_INFO_PROP_ID, pInfo, &size);
                ok(ret, "CertGetCertificateContextProperty failed: %08x\n",
                    GetLastError());
                if (ret)
                {
                    /* Sanity-check the key provider */
                    ok(!lstrcmpW(pInfo->pwszContainerName, cspNameW),
                        "Unexpected key container\n");
                    ok(!lstrcmpW(pInfo->pwszProvName, MS_DEF_PROV_W),
                        "Unexpected provider\n");
                    ok(pInfo->dwKeySpec == AT_KEYEXCHANGE,
                        "Expected AT_KEYEXCHANGE, got %d\n", pInfo->dwKeySpec);
                }
                HeapFree(GetProcessHeap(), 0, pInfo);
            }
        }

        CertFreeCertificateContext(context);
    }

    pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
        CRYPT_DELETEKEYSET);

    /* Acquire a CSP and generate an AT_KEYEXCHANGE key in it. */
    pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_DELETEKEYSET);
    ret = pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_NEWKEYSET);
    ok(ret, "CryptAcquireContext failed: %08x\n", GetLastError());

    context = pCertCreateSelfSignCertificate(csp, &name, 0, NULL, NULL, NULL,
     NULL, NULL);
    ok(!context && GetLastError() == NTE_NO_KEY,
     "Expected NTE_NO_KEY, got %08x\n", GetLastError());
    ret = CryptGenKey(csp, AT_KEYEXCHANGE, 0, &key);
    ok(ret, "CryptGenKey failed: %08x\n", GetLastError());
    CryptDestroyKey(key);

    memset(&info,0,sizeof(info));
    info.dwProvType = PROV_RSA_FULL;
    info.dwKeySpec = AT_SIGNATURE;
    info.pwszProvName = (LPWSTR) MS_DEF_PROV_W;
    info.pwszContainerName = cspNameW;
    /* This should fail because the CSP doesn't have the specified key. */
    SetLastError(0xdeadbeef);
    context = pCertCreateSelfSignCertificate(csp, &name, 0, &info, NULL, NULL,
        NULL, NULL);
    ok(context == NULL, "expected failure\n");
    if (context != NULL)
        CertFreeCertificateContext(context);
    else
        ok(GetLastError() == NTE_NO_KEY, "expected NTE_NO_KEY, got %08x\n",
            GetLastError());
    /* Again, with a CSP, AT_KEYEXCHANGE and key info. This succeeds because the
     * CSP has an AT_KEYEXCHANGE key in it.
     */
    info.dwKeySpec = AT_KEYEXCHANGE;
    SetLastError(0xdeadbeef);
    context = pCertCreateSelfSignCertificate(csp, &name, 0, &info, NULL, NULL,
        NULL, NULL);
    ok(context != NULL,
        "CertCreateSelfSignCertificate failed: %08x\n", GetLastError());
    if (context)
    {
        DWORD size = 0;

        /* The context must have a key provider info property */
        ret = CertGetCertificateContextProperty(context,
            CERT_KEY_PROV_INFO_PROP_ID, NULL, &size);
        ok(ret && size, "Expected non-zero key provider info\n");
        if (size)
        {
            PCRYPT_KEY_PROV_INFO pInfo = HeapAlloc(GetProcessHeap(), 0, size);

            if (pInfo)
            {
                ret = CertGetCertificateContextProperty(context,
                    CERT_KEY_PROV_INFO_PROP_ID, pInfo, &size);
                ok(ret, "CertGetCertificateContextProperty failed: %08x\n",
                    GetLastError());
                if (ret)
                {
                    /* Sanity-check the key provider */
                    ok(!lstrcmpW(pInfo->pwszContainerName, cspNameW),
                        "Unexpected key container\n");
                    ok(!lstrcmpW(pInfo->pwszProvName, MS_DEF_PROV_W),
                        "Unexpected provider\n");
                    ok(pInfo->dwKeySpec == AT_KEYEXCHANGE,
                        "Expected AT_KEYEXCHANGE, got %d\n", pInfo->dwKeySpec);
                }
                HeapFree(GetProcessHeap(), 0, pInfo);
            }
        }

        CertFreeCertificateContext(context);
    }

    CryptReleaseContext(csp, 0);
    ret = pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_DELETEKEYSET);
    ok(ret, "CryptAcquireContext failed: %08x\n", GetLastError());

}

static void testIntendedKeyUsage(void)
{
    BOOL ret;
    CERT_INFO info = { 0 };
    static char oid_key_usage[] = szOID_KEY_USAGE;
    /* A couple "key usages".  Really they're just encoded bits which aren't
     * necessarily restricted to the defined key usage values.
     */
    static BYTE usage1[] = { 0x03,0x03,0x00,0xff,0xff };
    static BYTE usage2[] = { 0x03,0x03,0x01,0xff,0xfe };
    static const BYTE expected_usage1[] = { 0xff,0xff,0x00,0x00 };
    static const BYTE expected_usage2[] = { 0xff,0xfe,0x00,0x00 };
    CERT_EXTENSION ext = { oid_key_usage, TRUE, { sizeof(usage1), usage1 } };
    BYTE usage_bytes[4];

    if (0)
    {
        /* Crash */
        CertGetIntendedKeyUsage(0, NULL, NULL, 0);
    }
    ret = CertGetIntendedKeyUsage(0, &info, NULL, 0);
    ok(!ret, "expected failure\n");
    ret = CertGetIntendedKeyUsage(0, &info, usage_bytes, sizeof(usage_bytes));
    ok(!ret, "expected failure\n");
    ret = CertGetIntendedKeyUsage(X509_ASN_ENCODING, &info, NULL, 0);
    ok(!ret, "expected failure\n");
    ret = CertGetIntendedKeyUsage(X509_ASN_ENCODING, &info, usage_bytes,
     sizeof(usage_bytes));
    ok(!ret, "expected failure\n");
    info.cExtension = 1;
    info.rgExtension = &ext;
    ret = CertGetIntendedKeyUsage(X509_ASN_ENCODING, &info, NULL, 0);
    ok(!ret, "expected failure\n");
    /* The unused bytes are filled with 0. */
    ret = CertGetIntendedKeyUsage(X509_ASN_ENCODING, &info, usage_bytes,
     sizeof(usage_bytes));
    ok(ret, "CertGetIntendedKeyUsage failed: %08x\n", GetLastError());
    ok(!memcmp(usage_bytes, expected_usage1, sizeof(expected_usage1)),
     "unexpected value\n");
    /* The usage bytes are copied in big-endian order. */
    ext.Value.cbData = sizeof(usage2);
    ext.Value.pbData = usage2;
    ret = CertGetIntendedKeyUsage(X509_ASN_ENCODING, &info, usage_bytes,
     sizeof(usage_bytes));
    ok(ret, "CertGetIntendedKeyUsage failed: %08x\n", GetLastError());
    ok(!memcmp(usage_bytes, expected_usage2, sizeof(expected_usage2)),
     "unexpected value\n");
}

static const LPCSTR keyUsages[] = { szOID_PKIX_KP_CODE_SIGNING,
 szOID_PKIX_KP_CLIENT_AUTH, szOID_RSA_RSA };

static void testKeyUsage(void)
{
    BOOL ret;
    PCCERT_CONTEXT context;
    DWORD size;

    /* Test base cases */
    ret = CertGetEnhancedKeyUsage(NULL, 0, NULL, NULL);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
     "Expected ERROR_INVALID_PARAMETER, got %08x\n", GetLastError());
    size = 1;
    ret = CertGetEnhancedKeyUsage(NULL, 0, NULL, &size);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
     "Expected ERROR_INVALID_PARAMETER, got %08x\n", GetLastError());
    size = 0;
    ret = CertGetEnhancedKeyUsage(NULL, 0, NULL, &size);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
     "Expected ERROR_INVALID_PARAMETER, got %08x\n", GetLastError());
    /* These crash
    ret = CertSetEnhancedKeyUsage(NULL, NULL);
    usage.cUsageIdentifier = 0;
    ret = CertSetEnhancedKeyUsage(NULL, &usage);
     */
    /* Test with a cert with no enhanced key usage extension */
    context = CertCreateCertificateContext(X509_ASN_ENCODING, bigCert,
     sizeof(bigCert));
    ok(context != NULL, "CertCreateCertificateContext failed: %08x\n",
     GetLastError());
    if (context)
    {
        static const char oid[] = "1.2.3.4";
        BYTE buf[sizeof(CERT_ENHKEY_USAGE) + 2 * (sizeof(LPSTR) + sizeof(oid))];
        PCERT_ENHKEY_USAGE pUsage = (PCERT_ENHKEY_USAGE)buf;

        ret = CertGetEnhancedKeyUsage(context, 0, NULL, NULL);
        ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
         "Expected ERROR_INVALID_PARAMETER, got %08x\n", GetLastError());
        size = 1;
        ret = CertGetEnhancedKeyUsage(context, 0, NULL, &size);
        if (ret)
        {
            /* Windows 2000, ME, or later: even though it succeeded, we expect
             * CRYPT_E_NOT_FOUND, which indicates there is no enhanced key
             * usage set for this cert (which implies it's valid for all uses.)
             */
            ok(GetLastError() == CRYPT_E_NOT_FOUND,
             "Expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());
            ok(size == sizeof(CERT_ENHKEY_USAGE), "Wrong size %d\n", size);
            ret = CertGetEnhancedKeyUsage(context, 0, pUsage, &size);
            ok(ret, "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
            ok(pUsage->cUsageIdentifier == 0, "Expected 0 usages, got %d\n",
             pUsage->cUsageIdentifier);
        }
        else
        {
            /* Windows NT, 95, or 98: it fails, and the last error is
             * CRYPT_E_NOT_FOUND.
             */
            ok(GetLastError() == CRYPT_E_NOT_FOUND,
             "Expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());
        }
        /* I can add a usage identifier when no key usage has been set */
        ret = CertAddEnhancedKeyUsageIdentifier(context, oid);
        ok(ret, "CertAddEnhancedKeyUsageIdentifier failed: %08x\n",
         GetLastError());
        size = sizeof(buf);
        ret = CertGetEnhancedKeyUsage(context,
         CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, pUsage, &size);
        ok(ret && GetLastError() == 0,
         "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
        ok(pUsage->cUsageIdentifier == 1, "Expected 1 usage, got %d\n",
         pUsage->cUsageIdentifier);
        if (pUsage->cUsageIdentifier)
            ok(!strcmp(pUsage->rgpszUsageIdentifier[0], oid),
             "Expected %s, got %s\n", oid, pUsage->rgpszUsageIdentifier[0]);
        /* Now set an empty key usage */
        pUsage->cUsageIdentifier = 0;
        ret = CertSetEnhancedKeyUsage(context, pUsage);
        ok(ret, "CertSetEnhancedKeyUsage failed: %08x\n", GetLastError());
        /* Shouldn't find it in the cert */
        size = sizeof(buf);
        ret = CertGetEnhancedKeyUsage(context,
         CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, pUsage, &size);
        ok(!ret && GetLastError() == CRYPT_E_NOT_FOUND,
         "Expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());
        /* Should find it as an extended property */
        ret = CertGetEnhancedKeyUsage(context,
         CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, pUsage, &size);
        ok(ret && GetLastError() == 0,
         "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
        ok(pUsage->cUsageIdentifier == 0, "Expected 0 usages, got %d\n",
         pUsage->cUsageIdentifier);
        /* Should find it as either */
        ret = CertGetEnhancedKeyUsage(context, 0, pUsage, &size);
        ok(ret && GetLastError() == 0,
         "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
        ok(pUsage->cUsageIdentifier == 0, "Expected 0 usages, got %d\n",
         pUsage->cUsageIdentifier);
        /* Add a usage identifier */
        ret = CertAddEnhancedKeyUsageIdentifier(context, oid);
        ok(ret, "CertAddEnhancedKeyUsageIdentifier failed: %08x\n",
         GetLastError());
        size = sizeof(buf);
        ret = CertGetEnhancedKeyUsage(context, 0, pUsage, &size);
        ok(ret && GetLastError() == 0,
         "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
        ok(pUsage->cUsageIdentifier == 1, "Expected 1 identifier, got %d\n",
         pUsage->cUsageIdentifier);
        if (pUsage->cUsageIdentifier)
            ok(!strcmp(pUsage->rgpszUsageIdentifier[0], oid),
             "Expected %s, got %s\n", oid, pUsage->rgpszUsageIdentifier[0]);
        /* Re-adding the same usage identifier succeeds, though it only adds
         * a duplicate usage identifier on versions prior to Vista
         */
        ret = CertAddEnhancedKeyUsageIdentifier(context, oid);
        ok(ret, "CertAddEnhancedKeyUsageIdentifier failed: %08x\n",
         GetLastError());
        size = sizeof(buf);
        ret = CertGetEnhancedKeyUsage(context, 0, pUsage, &size);
        ok(ret && GetLastError() == 0,
         "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
        ok(pUsage->cUsageIdentifier == 1 || pUsage->cUsageIdentifier == 2,
         "Expected 1 or 2 identifiers, got %d\n", pUsage->cUsageIdentifier);
        if (pUsage->cUsageIdentifier)
            ok(!strcmp(pUsage->rgpszUsageIdentifier[0], oid),
             "Expected %s, got %s\n", oid, pUsage->rgpszUsageIdentifier[0]);
        if (pUsage->cUsageIdentifier >= 2)
            ok(!strcmp(pUsage->rgpszUsageIdentifier[1], oid),
             "Expected %s, got %s\n", oid, pUsage->rgpszUsageIdentifier[1]);
        /* Now set a NULL extended property--this deletes the property. */
        ret = CertSetEnhancedKeyUsage(context, NULL);
        ok(ret, "CertSetEnhancedKeyUsage failed: %08x\n", GetLastError());
        SetLastError(0xbaadcafe);
        size = sizeof(buf);
        ret = CertGetEnhancedKeyUsage(context, 0, pUsage, &size);
        ok(ret || broken(!ret && GetLastError() == CRYPT_E_NOT_FOUND /* NT4 */),
	 "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
        ok(GetLastError() == CRYPT_E_NOT_FOUND,
         "Expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());

        CertFreeCertificateContext(context);
    }
    /* Now test with a cert with an enhanced key usage extension */
    context = CertCreateCertificateContext(X509_ASN_ENCODING, certWithUsage,
     sizeof(certWithUsage));
    ok(context != NULL, "CertCreateCertificateContext failed: %08x\n",
     GetLastError());
    if (context)
    {
        LPBYTE buf = NULL;
        DWORD bufSize = 0, i;

        /* The size may depend on what flags are used to query it, so I
         * realloc the buffer for each test.
         */
        ret = CertGetEnhancedKeyUsage(context,
         CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, NULL, &bufSize);
        ok(ret, "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
        buf = HeapAlloc(GetProcessHeap(), 0, bufSize);
        if (buf)
        {
            PCERT_ENHKEY_USAGE pUsage = (PCERT_ENHKEY_USAGE)buf;

            /* Should find it in the cert */
            size = bufSize;
            ret = CertGetEnhancedKeyUsage(context,
             CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, pUsage, &size);
            ok(ret && GetLastError() == 0,
             "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
            ok(pUsage->cUsageIdentifier == 3, "Expected 3 usages, got %d\n",
             pUsage->cUsageIdentifier);
            for (i = 0; i < pUsage->cUsageIdentifier; i++)
                ok(!strcmp(pUsage->rgpszUsageIdentifier[i], keyUsages[i]),
                 "Expected %s, got %s\n", keyUsages[i],
                 pUsage->rgpszUsageIdentifier[i]);
            HeapFree(GetProcessHeap(), 0, buf);
        }
        ret = CertGetEnhancedKeyUsage(context, 0, NULL, &bufSize);
        ok(ret, "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
        buf = HeapAlloc(GetProcessHeap(), 0, bufSize);
        if (buf)
        {
            PCERT_ENHKEY_USAGE pUsage = (PCERT_ENHKEY_USAGE)buf;

            /* Should find it as either */
            size = bufSize;
            ret = CertGetEnhancedKeyUsage(context, 0, pUsage, &size);
            /* In Windows, GetLastError returns CRYPT_E_NOT_FOUND not found
             * here, even though the return is successful and the usage id
             * count is positive.  I don't enforce that here.
             */
            ok(ret,
             "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
            ok(pUsage->cUsageIdentifier == 3, "Expected 3 usages, got %d\n",
             pUsage->cUsageIdentifier);
            for (i = 0; i < pUsage->cUsageIdentifier; i++)
                ok(!strcmp(pUsage->rgpszUsageIdentifier[i], keyUsages[i]),
                 "Expected %s, got %s\n", keyUsages[i],
                 pUsage->rgpszUsageIdentifier[i]);
            HeapFree(GetProcessHeap(), 0, buf);
        }
        /* Shouldn't find it as an extended property */
        ret = CertGetEnhancedKeyUsage(context,
         CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, NULL, &size);
        ok(!ret && GetLastError() == CRYPT_E_NOT_FOUND,
         "Expected CRYPT_E_NOT_FOUND, got %08x\n", GetLastError());
        /* Adding a usage identifier overrides the cert's usage!? */
        ret = CertAddEnhancedKeyUsageIdentifier(context, szOID_RSA_RSA);
        ok(ret, "CertAddEnhancedKeyUsageIdentifier failed: %08x\n",
         GetLastError());
        ret = CertGetEnhancedKeyUsage(context, 0, NULL, &bufSize);
        ok(ret, "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
        buf = HeapAlloc(GetProcessHeap(), 0, bufSize);
        if (buf)
        {
            PCERT_ENHKEY_USAGE pUsage = (PCERT_ENHKEY_USAGE)buf;

            /* Should find it as either */
            size = bufSize;
            ret = CertGetEnhancedKeyUsage(context, 0, pUsage, &size);
            ok(ret,
             "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
            ok(pUsage->cUsageIdentifier == 1, "Expected 1 usage, got %d\n",
             pUsage->cUsageIdentifier);
            ok(!strcmp(pUsage->rgpszUsageIdentifier[0], szOID_RSA_RSA),
             "Expected %s, got %s\n", szOID_RSA_RSA,
             pUsage->rgpszUsageIdentifier[0]);
            HeapFree(GetProcessHeap(), 0, buf);
        }
        /* But querying the cert directly returns its usage */
        ret = CertGetEnhancedKeyUsage(context,
         CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, NULL, &bufSize);
        ok(ret, "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
        buf = HeapAlloc(GetProcessHeap(), 0, bufSize);
        if (buf)
        {
            PCERT_ENHKEY_USAGE pUsage = (PCERT_ENHKEY_USAGE)buf;

            size = bufSize;
            ret = CertGetEnhancedKeyUsage(context,
             CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, pUsage, &size);
            ok(ret,
             "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
            ok(pUsage->cUsageIdentifier == 3, "Expected 3 usages, got %d\n",
             pUsage->cUsageIdentifier);
            for (i = 0; i < pUsage->cUsageIdentifier; i++)
                ok(!strcmp(pUsage->rgpszUsageIdentifier[i], keyUsages[i]),
                 "Expected %s, got %s\n", keyUsages[i],
                 pUsage->rgpszUsageIdentifier[i]);
            HeapFree(GetProcessHeap(), 0, buf);
        }
        /* And removing the only usage identifier in the extended property
         * results in the cert's key usage being found.
         */
        ret = CertRemoveEnhancedKeyUsageIdentifier(context, szOID_RSA_RSA);
        ok(ret, "CertRemoveEnhancedKeyUsage failed: %08x\n", GetLastError());
        ret = CertGetEnhancedKeyUsage(context, 0, NULL, &bufSize);
        ok(ret, "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
        buf = HeapAlloc(GetProcessHeap(), 0, bufSize);
        if (buf)
        {
            PCERT_ENHKEY_USAGE pUsage = (PCERT_ENHKEY_USAGE)buf;

            /* Should find it as either */
            size = bufSize;
            ret = CertGetEnhancedKeyUsage(context, 0, pUsage, &size);
            ok(ret,
             "CertGetEnhancedKeyUsage failed: %08x\n", GetLastError());
            ok(pUsage->cUsageIdentifier == 3, "Expected 3 usages, got %d\n",
             pUsage->cUsageIdentifier);
            for (i = 0; i < pUsage->cUsageIdentifier; i++)
                ok(!strcmp(pUsage->rgpszUsageIdentifier[i], keyUsages[i]),
                 "Expected %s, got %s\n", keyUsages[i],
                 pUsage->rgpszUsageIdentifier[i]);
            HeapFree(GetProcessHeap(), 0, buf);
        }

        CertFreeCertificateContext(context);
    }
}

static const BYTE cert2WithUsage[] = {
0x30,0x81,0x89,0x02,0x01,0x01,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,
0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,
0x6e,0x67,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,
0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,
0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x15,0x31,0x13,0x30,0x11,
0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,
0x67,0x00,0x30,0x07,0x30,0x02,0x06,0x00,0x03,0x01,0x00,0xa3,0x25,0x30,0x23,
0x30,0x21,0x06,0x03,0x55,0x1d,0x25,0x01,0x01,0xff,0x04,0x17,0x30,0x15,0x06,
0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x02,0x06,0x09,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x01,0x01,0x01 };

static void testGetValidUsages(void)
{
    static const LPCSTR expectedOIDs[] = {
     "1.3.6.1.5.5.7.3.3",
     "1.3.6.1.5.5.7.3.2",
     "1.2.840.113549.1.1.1",
    };
    static const LPCSTR expectedOIDs2[] = {
     "1.3.6.1.5.5.7.3.2",
     "1.2.840.113549.1.1.1",
    };
    BOOL ret;
    int numOIDs;
    DWORD size;
    LPSTR *oids = NULL;
    PCCERT_CONTEXT contexts[3];

    if (!pCertGetValidUsages)
    {
        win_skip("CertGetValidUsages() is not available\n");
        return;
    }

    /* Crash
    ret = pCertGetValidUsages(0, NULL, NULL, NULL, NULL);
    ret = pCertGetValidUsages(0, NULL, NULL, NULL, &size);
     */
    contexts[0] = NULL;
    size = numOIDs = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = pCertGetValidUsages(1, &contexts[0], &numOIDs, NULL, &size);
    ok(ret, "CertGetValidUsages failed: %d\n", GetLastError());
    ok(numOIDs == -1, "Expected -1, got %d\n", numOIDs);
    ok(size == 0, "Expected size 0, got %d\n", size);
    contexts[0] = CertCreateCertificateContext(X509_ASN_ENCODING, bigCert,
     sizeof(bigCert));
    contexts[1] = CertCreateCertificateContext(X509_ASN_ENCODING, certWithUsage,
     sizeof(certWithUsage));
    contexts[2] = CertCreateCertificateContext(X509_ASN_ENCODING,
     cert2WithUsage, sizeof(cert2WithUsage));
    size = numOIDs = 0xdeadbeef;
    ret = pCertGetValidUsages(0, NULL, &numOIDs, NULL, &size);
    ok(ret, "CertGetValidUsages failed: %08x\n", GetLastError());
    ok(numOIDs == -1, "Expected -1, got %d\n", numOIDs);
    ok(size == 0, "Expected size 0, got %d\n", size);
    size = numOIDs = 0xdeadbeef;
    ret = pCertGetValidUsages(1, contexts, &numOIDs, NULL, &size);
    ok(ret, "CertGetValidUsages failed: %08x\n", GetLastError());
    ok(numOIDs == -1, "Expected -1, got %d\n", numOIDs);
    ok(size == 0, "Expected size 0, got %d\n", size);
    ret = pCertGetValidUsages(1, &contexts[1], &numOIDs, NULL, &size);
    ok(ret, "CertGetValidUsages failed: %08x\n", GetLastError());
    ok(numOIDs == 3, "Expected 3, got %d\n", numOIDs);
    ok(size, "Expected non-zero size\n");
    oids = HeapAlloc(GetProcessHeap(), 0, size);
    if (oids)
    {
        int i;
        DWORD smallSize = 1;

        SetLastError(0xdeadbeef);
        ret = pCertGetValidUsages(1, &contexts[1], &numOIDs, oids, &smallSize);
        ok(!ret && GetLastError() == ERROR_MORE_DATA,
         "Expected ERROR_MORE_DATA, got %d\n", GetLastError());
        ret = pCertGetValidUsages(1, &contexts[1], &numOIDs, oids, &size);
        ok(ret, "CertGetValidUsages failed: %08x\n", GetLastError());
        for (i = 0; i < numOIDs; i++)
            ok(!lstrcmpA(oids[i], expectedOIDs[i]), "unexpected OID %s\n",
             oids[i]);
        HeapFree(GetProcessHeap(), 0, oids);
    }
    numOIDs = 0xdeadbeef;
    /* Oddly enough, this crashes when the number of contexts is not 1:
    ret = pCertGetValidUsages(2, contexts, &numOIDs, NULL, &size);
     * but setting size to 0 allows it to succeed:
     */
    size = 0;
    ret = pCertGetValidUsages(2, contexts, &numOIDs, NULL, &size);
    ok(ret, "CertGetValidUsages failed: %08x\n", GetLastError());
    ok(numOIDs == 3, "Expected 3, got %d\n", numOIDs);
    ok(size, "Expected non-zero size\n");
    oids = HeapAlloc(GetProcessHeap(), 0, size);
    if (oids)
    {
        int i;

        ret = pCertGetValidUsages(1, &contexts[1], &numOIDs, oids, &size);
        ok(ret, "CertGetValidUsages failed: %08x\n", GetLastError());
        for (i = 0; i < numOIDs; i++)
            ok(!lstrcmpA(oids[i], expectedOIDs[i]), "unexpected OID %s\n",
             oids[i]);
        HeapFree(GetProcessHeap(), 0, oids);
    }
    numOIDs = 0xdeadbeef;
    size = 0;
    ret = pCertGetValidUsages(1, &contexts[2], &numOIDs, NULL, &size);
    ok(ret, "CertGetValidUsages failed: %08x\n", GetLastError());
    ok(numOIDs == 2, "Expected 2, got %d\n", numOIDs);
    ok(size, "Expected non-zero size\n");
    oids = HeapAlloc(GetProcessHeap(), 0, size);
    if (oids)
    {
        int i;

        ret = pCertGetValidUsages(1, &contexts[2], &numOIDs, oids, &size);
        ok(ret, "CertGetValidUsages failed: %08x\n", GetLastError());
        for (i = 0; i < numOIDs; i++)
            ok(!lstrcmpA(oids[i], expectedOIDs2[i]), "unexpected OID %s\n",
             oids[i]);
        HeapFree(GetProcessHeap(), 0, oids);
    }
    numOIDs = 0xdeadbeef;
    size = 0;
    ret = pCertGetValidUsages(3, contexts, &numOIDs, NULL, &size);
    ok(ret, "CertGetValidUsages failed: %08x\n", GetLastError());
    ok(numOIDs == 2, "Expected 2, got %d\n", numOIDs);
    ok(size, "Expected non-zero size\n");
    oids = HeapAlloc(GetProcessHeap(), 0, size);
    if (oids)
    {
        int i;

        ret = pCertGetValidUsages(3, contexts, &numOIDs, oids, &size);
        ok(ret, "CertGetValidUsages failed: %08x\n", GetLastError());
        for (i = 0; i < numOIDs; i++)
            ok(!lstrcmpA(oids[i], expectedOIDs2[i]), "unexpected OID %s\n",
             oids[i]);
        HeapFree(GetProcessHeap(), 0, oids);
    }
    CertFreeCertificateContext(contexts[0]);
    CertFreeCertificateContext(contexts[1]);
    CertFreeCertificateContext(contexts[2]);
}

static BYTE cn[] = {
0x30,0x14,0x31,0x12,0x30,0x10,0x06,0x03,0x55,0x04,0x03,0x13,0x09,0x4a,0x75,
0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67 };
static BYTE cnWithLeadingSpace[] = {
0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x20,0x4a,
0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67 };
static BYTE cnWithTrailingSpace[] = {
0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,
0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x20 };
static BYTE cnWithIntermediateSpace[] = {
0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,
0x61,0x6e,0x20,0x20,0x4c,0x61,0x6e,0x67 };
static BYTE cnThenO[] = {
0x30,0x2d,0x31,0x2b,0x30,0x10,0x06,0x03,0x55,0x04,0x03,0x13,0x09,0x4a,0x75,
0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x30,0x17,0x06,0x03,0x55,0x04,0x0a,0x13,
0x10,0x54,0x68,0x65,0x20,0x57,0x69,0x6e,0x65,0x20,0x50,0x72,0x6f,0x6a,0x65,
0x63,0x74 };
static BYTE oThenCN[] = {
0x30,0x2d,0x31,0x2b,0x30,0x10,0x06,0x03,0x55,0x04,0x0a,0x13,0x09,0x4a,0x75,
0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x30,0x17,0x06,0x03,0x55,0x04,0x03,0x13,
0x10,0x54,0x68,0x65,0x20,0x57,0x69,0x6e,0x65,0x20,0x50,0x72,0x6f,0x6a,0x65,
0x63,0x74 };

static void testCompareCertName(void)
{
    static BYTE bogus[] = { 1, 2, 3, 4 };
    static BYTE bogusPrime[] = { 0, 1, 2, 3, 4 };
    static BYTE emptyPrime[] = { 0x30, 0x00, 0x01 };
    BOOL ret;
    CERT_NAME_BLOB blob1, blob2;

    /* crashes
    ret = CertCompareCertificateName(0, NULL, NULL);
     */
    /* An empty name checks against itself.. */
    blob1.pbData = emptyCert;
    blob1.cbData = sizeof(emptyCert);
    ret = CertCompareCertificateName(0, &blob1, &blob1);
    ok(ret, "CertCompareCertificateName failed: %08x\n", GetLastError());
    /* It doesn't have to be a valid encoded name.. */
    blob1.pbData = bogus;
    blob1.cbData = sizeof(bogus);
    ret = CertCompareCertificateName(0, &blob1, &blob1);
    ok(ret, "CertCompareCertificateName failed: %08x\n", GetLastError());
    /* Leading zeroes matter.. */
    blob2.pbData = bogusPrime;
    blob2.cbData = sizeof(bogusPrime);
    ret = CertCompareCertificateName(0, &blob1, &blob2);
    ok(!ret, "Expected failure\n");
    /* As do trailing extra bytes. */
    blob2.pbData = emptyPrime;
    blob2.cbData = sizeof(emptyPrime);
    ret = CertCompareCertificateName(0, &blob1, &blob2);
    ok(!ret, "Expected failure\n");
    /* Tests to show that CertCompareCertificateName doesn't decode the name
     * to remove spaces, or to do an order-independent comparison.
     */
    /* Compare CN="Juan Lang" with CN=" Juan Lang" */
    blob1.pbData = cn;
    blob1.cbData = sizeof(cn);
    blob2.pbData = cnWithLeadingSpace;
    blob2.cbData = sizeof(cnWithLeadingSpace);
    ret = CertCompareCertificateName(0, &blob1, &blob2);
    ok(!ret, "Expected failure\n");
    ret = CertCompareCertificateName(X509_ASN_ENCODING, &blob1, &blob2);
    ok(!ret, "Expected failure\n");
    /* Compare CN="Juan Lang" with CN="Juan Lang " */
    blob2.pbData = cnWithTrailingSpace;
    blob2.cbData = sizeof(cnWithTrailingSpace);
    ret = CertCompareCertificateName(0, &blob1, &blob2);
    ok(!ret, "Expected failure\n");
    ret = CertCompareCertificateName(X509_ASN_ENCODING, &blob1, &blob2);
    ok(!ret, "Expected failure\n");
    /* Compare CN="Juan Lang" with CN="Juan  Lang" */
    blob2.pbData = cnWithIntermediateSpace;
    blob2.cbData = sizeof(cnWithIntermediateSpace);
    ret = CertCompareCertificateName(0, &blob1, &blob2);
    ok(!ret, "Expected failure\n");
    ret = CertCompareCertificateName(X509_ASN_ENCODING, &blob1, &blob2);
    ok(!ret, "Expected failure\n");
    /* Compare 'CN="Juan Lang", O="The Wine Project"' with
     * 'O="The Wine Project", CN="Juan Lang"'
     */
    blob1.pbData = cnThenO;
    blob1.cbData = sizeof(cnThenO);
    blob2.pbData = oThenCN;
    blob2.cbData = sizeof(oThenCN);
    ret = CertCompareCertificateName(0, &blob1, &blob2);
    ok(!ret, "Expected failure\n");
    ret = CertCompareCertificateName(X509_ASN_ENCODING, &blob1, &blob2);
    ok(!ret, "Expected failure\n");
}

static void testIsRDNAttrsInCertificateName(void)
{
    static char oid_1_2_3[] = "1.2.3";
    static char oid_common_name[] = szOID_COMMON_NAME;
    static char oid_organization[] = szOID_ORGANIZATION_NAME;
    static char juan[] = "Juan Lang";
    static char juan_with_leading_space[] = " Juan Lang";
    static char juan_with_intermediate_space[] = "Juan  Lang";
    static char juan_with_trailing_space[] = "Juan Lang ";
    static char juan_lower_case[] = "juan lang";
    static WCHAR juanW[] = { 'J','u','a','n',' ','L','a','n','g',0 };
    static char the_wine_project[] = "The Wine Project";
    BOOL ret;
    CERT_NAME_BLOB name;
    CERT_RDN_ATTR attr[2];
    CERT_RDN rdn = { 0, NULL };

    name.cbData = sizeof(cn);
    name.pbData = cn;
    if (0)
    {
        /* Crash */
        CertIsRDNAttrsInCertificateName(0, 0, NULL, NULL);
        CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, NULL);
    }
    SetLastError(0xdeadbeef);
    ret = CertIsRDNAttrsInCertificateName(0, 0, &name, NULL);
    ok(!ret && GetLastError() == ERROR_FILE_NOT_FOUND,
     "expected ERROR_FILE_NOT_FOUND, got %08x\n", GetLastError());
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, &rdn);
    ok(ret, "CertIsRDNAttrsInCertificateName failed: %08x\n", GetLastError());
    attr[0].pszObjId = oid_1_2_3;
    rdn.rgRDNAttr = attr;
    rdn.cRDNAttr = 1;
    SetLastError(0xdeadbeef);
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, &rdn);
    ok(!ret && GetLastError() == CRYPT_E_NO_MATCH,
     "expected CRYPT_E_NO_MATCH, got %08x\n", GetLastError());
    attr[0].pszObjId = oid_common_name;
    attr[0].dwValueType = CERT_RDN_PRINTABLE_STRING;
    attr[0].Value.cbData = strlen(juan);
    attr[0].Value.pbData = (BYTE *)juan;
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, &rdn);
    ok(ret, "CertIsRDNAttrsInCertificateName failed: %08x\n", GetLastError());
    /* Again, spaces are not removed for name comparison. */
    attr[0].Value.cbData = strlen(juan_with_leading_space);
    attr[0].Value.pbData = (BYTE *)juan_with_leading_space;
    SetLastError(0xdeadbeef);
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, &rdn);
    ok(!ret && GetLastError() == CRYPT_E_NO_MATCH,
     "expected CRYPT_E_NO_MATCH, got %08x\n", GetLastError());
    attr[0].Value.cbData = strlen(juan_with_intermediate_space);
    attr[0].Value.pbData = (BYTE *)juan_with_intermediate_space;
    SetLastError(0xdeadbeef);
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, &rdn);
    ok(!ret && GetLastError() == CRYPT_E_NO_MATCH,
     "expected CRYPT_E_NO_MATCH, got %08x\n", GetLastError());
    attr[0].Value.cbData = strlen(juan_with_trailing_space);
    attr[0].Value.pbData = (BYTE *)juan_with_trailing_space;
    SetLastError(0xdeadbeef);
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, &rdn);
    ok(!ret && GetLastError() == CRYPT_E_NO_MATCH,
     "expected CRYPT_E_NO_MATCH, got %08x\n", GetLastError());
    /* The lower case name isn't matched unless a case insensitive match is
     * specified.
     */
    attr[0].Value.cbData = strlen(juan_lower_case);
    attr[0].Value.pbData = (BYTE *)juan_lower_case;
    SetLastError(0xdeadbeef);
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, &rdn);
    ok(!ret && GetLastError() == CRYPT_E_NO_MATCH,
     "expected CRYPT_E_NO_MATCH, got %08x\n", GetLastError());
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING,
     CERT_CASE_INSENSITIVE_IS_RDN_ATTRS_FLAG, &name, &rdn);
    ok(ret ||
     broken(!ret && GetLastError() == CRYPT_E_NO_MATCH), /* Older crypt32 */
     "CertIsRDNAttrsInCertificateName failed: %08x\n", GetLastError());
    /* The values don't match unless they have the same RDN type */
    attr[0].dwValueType = CERT_RDN_UNICODE_STRING;
    attr[0].Value.cbData = lstrlenW(juanW) * sizeof(WCHAR);
    attr[0].Value.pbData = (BYTE *)juanW;
    SetLastError(0xdeadbeef);
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, &rdn);
    ok(!ret && GetLastError() == CRYPT_E_NO_MATCH,
     "expected CRYPT_E_NO_MATCH, got %08x\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING,
     CERT_UNICODE_IS_RDN_ATTRS_FLAG, &name, &rdn);
    ok(!ret && GetLastError() == CRYPT_E_NO_MATCH,
     "expected CRYPT_E_NO_MATCH, got %08x\n", GetLastError());
    attr[0].dwValueType = CERT_RDN_IA5_STRING;
    attr[0].Value.cbData = strlen(juan);
    attr[0].Value.pbData = (BYTE *)juan;
    SetLastError(0xdeadbeef);
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, &rdn);
    ok(!ret && GetLastError() == CRYPT_E_NO_MATCH,
     "expected CRYPT_E_NO_MATCH, got %08x\n", GetLastError());
    /* All attributes must be present */
    attr[0].dwValueType = CERT_RDN_PRINTABLE_STRING;
    attr[0].Value.cbData = strlen(juan);
    attr[0].Value.pbData = (BYTE *)juan;
    attr[1].pszObjId = oid_organization;
    attr[1].dwValueType = CERT_RDN_PRINTABLE_STRING;
    attr[1].Value.cbData = strlen(the_wine_project);
    attr[1].Value.pbData = (BYTE *)the_wine_project;
    rdn.cRDNAttr = 2;
    SetLastError(0xdeadbeef);
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, &rdn);
    ok(!ret && GetLastError() == CRYPT_E_NO_MATCH,
     "expected CRYPT_E_NO_MATCH, got %08x\n", GetLastError());
    /* Order also matters */
    name.pbData = cnThenO;
    name.cbData = sizeof(cnThenO);
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, &rdn);
    ok(ret, "CertIsRDNAttrsInCertificateName failed: %08x\n", GetLastError());
    name.pbData = oThenCN;
    name.cbData = sizeof(oThenCN);
    SetLastError(0xdeadbeef);
    ret = CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 0, &name, &rdn);
    ok(!ret && GetLastError() == CRYPT_E_NO_MATCH,
     "expected CRYPT_E_NO_MATCH, got %08x\n", GetLastError());
}

static BYTE int1[] = { 0x88, 0xff, 0xff, 0xff };
static BYTE int2[] = { 0x88, 0xff };
static BYTE int3[] = { 0x23, 0xff };
static BYTE int4[] = { 0x7f, 0x00 };
static BYTE int5[] = { 0x7f };
static BYTE int6[] = { 0x80, 0x00, 0x00, 0x00 };
static BYTE int7[] = { 0x80, 0x00 };

static struct IntBlobTest
{
    CRYPT_INTEGER_BLOB blob1;
    CRYPT_INTEGER_BLOB blob2;
    BOOL areEqual;
} intBlobs[] = {
 { { sizeof(int1), int1 }, { sizeof(int2), int2 }, TRUE },
 { { sizeof(int3), int3 }, { sizeof(int3), int3 }, TRUE },
 { { sizeof(int4), int4 }, { sizeof(int5), int5 }, TRUE },
 { { sizeof(int6), int6 }, { sizeof(int7), int7 }, TRUE },
 { { sizeof(int1), int1 }, { sizeof(int7), int7 }, FALSE },
};

static void testCompareIntegerBlob(void)
{
    DWORD i;
    BOOL ret;

    for (i = 0; i < ARRAY_SIZE(intBlobs); i++)
    {
        ret = CertCompareIntegerBlob(&intBlobs[i].blob1, &intBlobs[i].blob2);
        ok(ret == intBlobs[i].areEqual,
         "%d: expected blobs %s compare\n", i, intBlobs[i].areEqual ?
         "to" : "not to");
    }
}

static void testComparePublicKeyInfo(void)
{
    BOOL ret;
    CERT_PUBLIC_KEY_INFO info1 = { { 0 } }, info2 = { { 0 } };
    static CHAR oid_rsa_rsa[]     = szOID_RSA_RSA;
    static CHAR oid_rsa_sha1rsa[] = szOID_RSA_SHA1RSA;
    static CHAR oid_x957_dsa[]    = szOID_X957_DSA;
    static BYTE bits1[] = { 1, 0 };
    static BYTE bits2[] = { 0 };
    static BYTE bits3[] = { 1 };
    static BYTE bits4[] = { 0x30,8, 2,1,0x81, 2,3,1,0,1 }; /* ASN_SEQUENCE */
    static BYTE bits5[] = { 0x30,9, 2,2,0,0x81, 2,3,1,0,1 }; /* ASN_SEQUENCE */
    static BYTE bits6[] = { 0x30,9, 2,2,0,0x82, 2,3,1,0,1 }; /* ASN_SEQUENCE */
    static BYTE bits7[] = { 0x04,8, 2,1,0x81, 2,3,1,0,1 }; /* ASN_OCTETSTRING */
    static BYTE bits8[] = { 0x04,9, 2,2,0,0x81, 2,3,1,0,1 }; /* ASN_OCTETSTRING */
    static BYTE bits9[] = { 0x04,9, 2,2,0,0x82, 2,3,1,0,1 }; /* ASN_OCTETSTRING */

    /* crashes
    ret = CertComparePublicKeyInfo(0, NULL, NULL);
     */
    /* Empty public keys compare */
    ret = CertComparePublicKeyInfo(0, &info1, &info2);
    ok(ret, "CertComparePublicKeyInfo failed: %08x\n", GetLastError());
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info2);
    ok(ret, "CertComparePublicKeyInfo failed: %08x\n", GetLastError());

    /* Different OIDs appear to compare */
    info1.Algorithm.pszObjId = oid_rsa_rsa;
    info2.Algorithm.pszObjId = oid_rsa_sha1rsa;
    ret = CertComparePublicKeyInfo(0, &info1, &info2);
    ok(ret, "CertComparePublicKeyInfo failed: %08x\n", GetLastError());
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info2);
    ok(ret, "CertComparePublicKeyInfo failed: %08x\n", GetLastError());

    info2.Algorithm.pszObjId = oid_x957_dsa;
    ret = CertComparePublicKeyInfo(0, &info1, &info2);
    ok(ret, "CertComparePublicKeyInfo failed: %08x\n", GetLastError());
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info2);
    ok(ret, "CertComparePublicKeyInfo failed: %08x\n", GetLastError());

    info1.PublicKey.cbData = sizeof(bits1);
    info1.PublicKey.pbData = bits1;
    info1.PublicKey.cUnusedBits = 0;
    info2.PublicKey.cbData = sizeof(bits1);
    info2.PublicKey.pbData = bits1;
    info2.PublicKey.cUnusedBits = 0;
    ret = CertComparePublicKeyInfo(0, &info1, &info2);
    ok(ret, "CertComparePublicKeyInfo failed: %08x\n", GetLastError());
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info2);
    ok(ret, "CertComparePublicKeyInfo failed: %08x\n", GetLastError());

    info2.Algorithm.pszObjId = oid_rsa_rsa;
    info1.PublicKey.cbData = sizeof(bits4);
    info1.PublicKey.pbData = bits4;
    info1.PublicKey.cUnusedBits = 0;
    info2.PublicKey.cbData = sizeof(bits5);
    info2.PublicKey.pbData = bits5;
    info2.PublicKey.cUnusedBits = 0;
    ret = CertComparePublicKeyInfo(0, &info1, &info2);
    ok(!ret, "CertComparePublicKeyInfo: as raw binary: keys should be unequal\n");
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info2);
    ok(ret, "CertComparePublicKeyInfo: as ASN.1 encoded: keys should be equal\n");

    info1.PublicKey.cUnusedBits = 1;
    info2.PublicKey.cUnusedBits = 5;
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info2);
    ok(ret, "CertComparePublicKeyInfo: ASN.1 encoding should ignore cUnusedBits\n");
    info1.PublicKey.cUnusedBits = 0;
    info2.PublicKey.cUnusedBits = 0;
    info1.PublicKey.cbData--; /* kill one byte, make ASN.1 encoded data invalid */
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info2);
    ok(!ret, "CertComparePublicKeyInfo: comparing bad ASN.1 encoded key should fail\n");
    /* Even though they compare in their used bits, these do not compare */
    info1.PublicKey.cbData = sizeof(bits2);
    info1.PublicKey.pbData = bits2;
    info1.PublicKey.cUnusedBits = 0;
    info2.PublicKey.cbData = sizeof(bits3);
    info2.PublicKey.pbData = bits3;
    info2.PublicKey.cUnusedBits = 1;
    ret = CertComparePublicKeyInfo(0, &info1, &info2);
    /* Simple (non-comparing) case */
    ok(!ret, "Expected keys not to compare\n");
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info2);
    ok(!ret, "Expected keys not to compare\n");

    info2.PublicKey.cbData = sizeof(bits1);
    info2.PublicKey.pbData = bits1;
    info2.PublicKey.cUnusedBits = 0;
    ret = CertComparePublicKeyInfo(0, &info1, &info2);
    ok(!ret, "Expected keys not to compare\n");
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info2);
    ok(!ret, "Expected keys not to compare\n");

    info1.PublicKey.cbData = sizeof(bits7);
    info1.PublicKey.pbData = bits7;
    info1.PublicKey.cUnusedBits = 0;
    info2.PublicKey.cbData = sizeof(bits8);
    info2.PublicKey.pbData = bits8;
    info2.PublicKey.cUnusedBits = 0;
    ret = CertComparePublicKeyInfo(0, &info1, &info2);
    ok(!ret, "CertComparePublicKeyInfo: as raw binary: keys should be unequal\n");
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info2);
    ok(!ret, "CertComparePublicKeyInfo: as ASN.1 encoded: keys should be unequal\n");

    ret = CertComparePublicKeyInfo(0, &info1, &info1);
    ok(ret, "CertComparePublicKeyInfo: as raw binary: keys should be equal\n");
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info1);
    ok(ret, "CertComparePublicKeyInfo: as ASN.1 encoded: keys should be equal\n");
    info1.PublicKey.cbData--; /* kill one byte, make ASN.1 encoded data invalid */
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info1);
    ok(ret, "CertComparePublicKeyInfo: as ASN.1 encoded: keys should be equal\n");

    /* ASN.1 encoded non-comparing case */
    info1.PublicKey.cbData = sizeof(bits5);
    info1.PublicKey.pbData = bits5;
    info1.PublicKey.cUnusedBits = 0;
    info2.PublicKey.cbData = sizeof(bits6);
    info2.PublicKey.pbData = bits6;
    info2.PublicKey.cUnusedBits = 0;
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info2);
    ok(!ret, "CertComparePublicKeyInfo: different keys should be unequal\n");

    /* ASN.1 encoded non-comparing case */
    info1.PublicKey.cbData = sizeof(bits8);
    info1.PublicKey.pbData = bits8;
    info1.PublicKey.cUnusedBits = 0;
    info2.PublicKey.cbData = sizeof(bits9);
    info2.PublicKey.pbData = bits9;
    info2.PublicKey.cUnusedBits = 0;
    ret = CertComparePublicKeyInfo(X509_ASN_ENCODING, &info1, &info2);
    ok(!ret, "CertComparePublicKeyInfo: different keys should be unequal\n");
}

static void testHashPublicKeyInfo(void)
{
    BOOL ret;
    CERT_PUBLIC_KEY_INFO info = { { 0 } };
    DWORD len;

    /* Crash
    ret = CryptHashPublicKeyInfo(0, 0, 0, 0, NULL, NULL, NULL);
    ret = CryptHashPublicKeyInfo(0, 0, 0, 0, &info, NULL, NULL);
     */
    ret = CryptHashPublicKeyInfo(0, 0, 0, 0, NULL, NULL, &len);
    ok(!ret && GetLastError() == ERROR_FILE_NOT_FOUND,
     "Expected ERROR_FILE_NOT_FOUND, got %08x\n", GetLastError());
    /* Crashes on some win9x boxes */
    if (0)
    {
        ret = CryptHashPublicKeyInfo(0, 0, 0, X509_ASN_ENCODING, NULL, NULL, &len);
        ok(!ret && GetLastError() == STATUS_ACCESS_VIOLATION,
         "Expected STATUS_ACCESS_VIOLATION, got %08x\n", GetLastError());
    }
    ret = CryptHashPublicKeyInfo(0, 0, 0, X509_ASN_ENCODING, &info, NULL, &len);
    ok(ret ||
     broken(!ret), /* win9x */
     "CryptHashPublicKeyInfo failed: %08x\n", GetLastError());
    if (ret)
    {
        ok(len == 16, "Expected hash size 16, got %d\n", len);
        if (len == 16)
        {
            static const BYTE emptyHash[] = { 0xb8,0x51,0x3a,0x31,0x0e,0x9f,0x40,
             0x36,0x9c,0x92,0x45,0x1b,0x9d,0xc8,0xf9,0xf6 };
            BYTE buf[16];

            ret = CryptHashPublicKeyInfo(0, 0, 0, X509_ASN_ENCODING, &info, buf,
             &len);
            ok(ret, "CryptHashPublicKeyInfo failed: %08x\n", GetLastError());
            ok(!memcmp(buf, emptyHash, len), "Unexpected hash\n");
        }
    }
}

static const BYTE md5SignedEmptyCertHash[] = { 0xfb,0x0f,0x66,0x82,0x66,0xd9,
 0xe5,0xf8,0xd8,0xa2,0x55,0x2b,0xe1,0xa5,0xd9,0x04 };

static void testHashToBeSigned(void)
{
    BOOL ret;
    DWORD size;
    BYTE hash[16];

    /* Crash */
    if (0)
    {
        CryptHashToBeSigned(0, 0, NULL, 0, NULL, NULL);
    }
    SetLastError(0xdeadbeef);
    ret = CryptHashToBeSigned(0, 0, NULL, 0, NULL, &size);
    ok(!ret && GetLastError() == ERROR_FILE_NOT_FOUND,
     "expected ERROR_FILE_NOT_FOUND, got %d\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptHashToBeSigned(0, X509_ASN_ENCODING, NULL, 0, NULL, &size);
    ok(!ret &&
     (GetLastError() == CRYPT_E_ASN1_EOD ||
      GetLastError() == OSS_BAD_ARG), /* win9x */
     "expected CRYPT_E_ASN1_EOD, got %08x\n", GetLastError());
    /* Can't sign anything:  has to be asn.1 encoded, at least */
    SetLastError(0xdeadbeef);
    ret = CryptHashToBeSigned(0, X509_ASN_ENCODING, int1, sizeof(int1),
     NULL, &size);
    ok(!ret &&
     (GetLastError() == CRYPT_E_ASN1_BADTAG ||
      GetLastError() == OSS_MORE_INPUT), /* win9x */
     "expected CRYPT_E_ASN1_BADTAG, got %08x\n", GetLastError());
    /* Can't be empty, either */
    SetLastError(0xdeadbeef);
    ret = CryptHashToBeSigned(0, X509_ASN_ENCODING, emptyCert,
     sizeof(emptyCert), NULL, &size);
    ok(!ret &&
     (GetLastError() == CRYPT_E_ASN1_CORRUPT ||
      GetLastError() == OSS_DATA_ERROR), /* win9x */
     "expected CRYPT_E_ASN1_CORRUPT, got %08x\n", GetLastError());
    /* Signing a cert works */
    ret = CryptHashToBeSigned(0, X509_ASN_ENCODING, md5SignedEmptyCert,
     sizeof(md5SignedEmptyCert), NULL, &size);
    ok(ret ||
     broken(!ret), /* win9x */
     "CryptHashToBeSigned failed: %08x\n", GetLastError());
    if (ret)
    {
        ok(size == sizeof(md5SignedEmptyCertHash), "unexpected size %d\n", size);
    }

    ret = CryptHashToBeSigned(0, X509_ASN_ENCODING, md5SignedEmptyCert,
     sizeof(md5SignedEmptyCert), hash, &size);
    ok(ret || broken(!ret && GetLastError() == NTE_BAD_ALGID) /* NT4 */,
     "CryptHashToBeSigned failed: %08x\n", GetLastError());

    ok(!memcmp(hash, md5SignedEmptyCertHash, size), "unexpected value\n");
}

static void testCompareCert(void)
{
    CERT_INFO info1 = { 0 }, info2 = { 0 };
    BOOL ret;

    /* Crashes */
    if (0)
        CertCompareCertificate(X509_ASN_ENCODING, NULL, NULL);

    /* Certs with the same issuer and serial number are equal, even if they
     * differ in other respects (like subject).
     */
    info1.SerialNumber.pbData = serialNum;
    info1.SerialNumber.cbData = sizeof(serialNum);
    info1.Issuer.pbData = subjectName;
    info1.Issuer.cbData = sizeof(subjectName);
    info1.Subject.pbData = subjectName2;
    info1.Subject.cbData = sizeof(subjectName2);
    info2.SerialNumber.pbData = serialNum;
    info2.SerialNumber.cbData = sizeof(serialNum);
    info2.Issuer.pbData = subjectName;
    info2.Issuer.cbData = sizeof(subjectName);
    info2.Subject.pbData = subjectName;
    info2.Subject.cbData = sizeof(subjectName);
    ret = CertCompareCertificate(X509_ASN_ENCODING, &info1, &info2);
    ok(ret, "Expected certs to be equal\n");

    info2.Issuer.pbData = subjectName2;
    info2.Issuer.cbData = sizeof(subjectName2);
    ret = CertCompareCertificate(X509_ASN_ENCODING, &info1, &info2);
    ok(!ret, "Expected certs not to be equal\n");
}

static void testVerifySubjectCert(void)
{
    BOOL ret;
    DWORD flags;
    PCCERT_CONTEXT context1, context2;

    /* Crashes
    ret = CertVerifySubjectCertificateContext(NULL, NULL, NULL);
     */
    flags = 0;
    ret = CertVerifySubjectCertificateContext(NULL, NULL, &flags);
    ok(ret, "CertVerifySubjectCertificateContext failed; %08x\n",
     GetLastError());
    flags = CERT_STORE_NO_CRL_FLAG;
    ret = CertVerifySubjectCertificateContext(NULL, NULL, &flags);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());

    flags = 0;
    context1 = CertCreateCertificateContext(X509_ASN_ENCODING, bigCert,
     sizeof(bigCert));
    ret = CertVerifySubjectCertificateContext(NULL, context1, &flags);
    ok(ret, "CertVerifySubjectCertificateContext failed; %08x\n",
     GetLastError());
    ret = CertVerifySubjectCertificateContext(context1, NULL, &flags);
    ok(ret, "CertVerifySubjectCertificateContext failed; %08x\n",
     GetLastError());
    ret = CertVerifySubjectCertificateContext(context1, context1, &flags);
    ok(ret, "CertVerifySubjectCertificateContext failed; %08x\n",
     GetLastError());

    context2 = CertCreateCertificateContext(X509_ASN_ENCODING,
     bigCertWithDifferentSubject, sizeof(bigCertWithDifferentSubject));
    SetLastError(0xdeadbeef);
    ret = CertVerifySubjectCertificateContext(context1, context2, &flags);
    ok(ret, "CertVerifySubjectCertificateContext failed; %08x\n",
     GetLastError());
    flags = CERT_STORE_REVOCATION_FLAG;
    ret = CertVerifySubjectCertificateContext(context1, context2, &flags);
    ok(ret, "CertVerifySubjectCertificateContext failed; %08x\n",
     GetLastError());
    ok(flags == (CERT_STORE_REVOCATION_FLAG | CERT_STORE_NO_CRL_FLAG),
     "Expected CERT_STORE_REVOCATION_FLAG | CERT_STORE_NO_CRL_FLAG, got %08x\n",
     flags);
    flags = CERT_STORE_SIGNATURE_FLAG;
    ret = CertVerifySubjectCertificateContext(context1, context2, &flags);
    ok(ret, "CertVerifySubjectCertificateContext failed; %08x\n",
     GetLastError());
    ok(flags == CERT_STORE_SIGNATURE_FLAG,
     "Expected CERT_STORE_SIGNATURE_FLAG, got %08x\n", flags);
    CertFreeCertificateContext(context2);

    CertFreeCertificateContext(context1);
}

static const BYTE rootWithKeySignAndCRLSign[] = {
0x30,0x82,0x01,0xdf,0x30,0x82,0x01,0x4c,0xa0,0x03,0x02,0x01,0x02,0x02,0x10,
0x5b,0xc7,0x0b,0x27,0x99,0xbb,0x2e,0x99,0x47,0x9d,0x45,0x4e,0x7c,0x1a,0xca,
0xe8,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1d,0x05,0x00,0x30,0x10,0x31,
0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x03,0x13,0x05,0x43,0x65,0x72,0x74,0x31,
0x30,0x1e,0x17,0x0d,0x30,0x37,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,
0x30,0x5a,0x17,0x0d,0x30,0x37,0x31,0x32,0x33,0x31,0x32,0x33,0x35,0x39,0x35,
0x39,0x5a,0x30,0x10,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x03,0x13,0x05,
0x43,0x65,0x72,0x74,0x31,0x30,0x81,0x9f,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x81,0x8d,0x00,0x30,0x81,0x89,
0x02,0x81,0x81,0x00,0xad,0x7e,0xca,0xf3,0xe5,0x99,0xc2,0x2a,0xca,0x50,0x82,
0x7c,0x2d,0xa4,0x81,0xcd,0x0d,0x0d,0x86,0xd7,0xd8,0xb2,0xde,0xc5,0xc3,0x34,
0x9e,0x07,0x78,0x08,0x11,0x12,0x2d,0x21,0x0a,0x09,0x07,0x14,0x03,0x7a,0xe7,
0x3b,0x58,0xf1,0xde,0x3e,0x01,0x25,0x93,0xab,0x8f,0xce,0x1f,0xc1,0x33,0x91,
0xfe,0x59,0xb9,0x3b,0x9e,0x95,0x12,0x89,0x8e,0xc3,0x4b,0x98,0x1b,0x99,0xc5,
0x07,0xe2,0xdf,0x15,0x4c,0x39,0x76,0x06,0xad,0xdb,0x16,0x06,0x49,0xba,0xcd,
0x0f,0x07,0xd6,0xea,0x27,0xa6,0xfe,0x3d,0x88,0xe5,0x97,0x45,0x72,0xb6,0x1c,
0xc0,0x1c,0xb1,0xa2,0x89,0xe8,0x37,0x9e,0xf6,0x2a,0xcf,0xd5,0x1f,0x2f,0x35,
0x5e,0x8f,0x3a,0x9c,0x61,0xb1,0xf1,0x6c,0xff,0x8c,0xb2,0x2f,0x02,0x03,0x01,
0x00,0x01,0xa3,0x42,0x30,0x40,0x30,0x0e,0x06,0x03,0x55,0x1d,0x0f,0x01,0x01,
0xff,0x04,0x04,0x03,0x02,0x00,0x06,0x30,0x0f,0x06,0x03,0x55,0x1d,0x13,0x01,
0x01,0xff,0x04,0x05,0x30,0x03,0x01,0x01,0xff,0x30,0x1d,0x06,0x03,0x55,0x1d,
0x0e,0x04,0x16,0x04,0x14,0x14,0x8c,0x16,0xbb,0xbe,0x70,0xa2,0x28,0x89,0xa0,
0x58,0xff,0x98,0xbd,0xa8,0x24,0x2b,0x8a,0xe9,0x9a,0x30,0x09,0x06,0x05,0x2b,
0x0e,0x03,0x02,0x1d,0x05,0x00,0x03,0x81,0x81,0x00,0x74,0xcb,0x21,0xfd,0x2d,
0x25,0xdc,0xa5,0xaa,0xa1,0x26,0xdc,0x8b,0x40,0x11,0x64,0xae,0x5c,0x71,0x3c,
0x28,0xbc,0xf9,0xb3,0xcb,0xa5,0x94,0xb2,0x8d,0x4c,0x23,0x2b,0x9b,0xde,0x2c,
0x4c,0x30,0x04,0xc6,0x88,0x10,0x2f,0x53,0xfd,0x6c,0x82,0xf1,0x13,0xfb,0xda,
0x27,0x75,0x25,0x48,0xe4,0x72,0x09,0x2a,0xee,0xb4,0x1e,0xc9,0x55,0xf5,0xf7,
0x82,0x91,0xd8,0x4b,0xe4,0x3a,0xfe,0x97,0x87,0xdf,0xfb,0x15,0x5a,0x12,0x3e,
0x12,0xe6,0xad,0x40,0x0b,0xcf,0xee,0x1a,0x44,0xe0,0x83,0xb2,0x67,0x94,0xd4,
0x2e,0x7c,0xf2,0x06,0x9d,0xb3,0x3b,0x7e,0x2f,0xda,0x25,0x66,0x7e,0xa7,0x1f,
0x45,0xd4,0xf5,0xe3,0xdf,0x2a,0xf1,0x18,0x28,0x20,0xb5,0xf8,0xf5,0x8d,0x7a,
0x2e,0x84,0xee };
static const BYTE eeCert[] = {
0x30,0x82,0x01,0xb9,0x30,0x82,0x01,0x22,0xa0,0x03,0x02,0x01,0x02,0x02,0x01,
0x01,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,
0x00,0x30,0x10,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x03,0x13,0x05,0x43,
0x65,0x72,0x74,0x31,0x30,0x1e,0x17,0x0d,0x30,0x37,0x30,0x35,0x30,0x31,0x30,
0x30,0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,0x30,0x37,0x31,0x30,0x30,0x31,0x30,
0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x10,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,
0x04,0x03,0x13,0x05,0x43,0x65,0x72,0x74,0x32,0x30,0x81,0x9f,0x30,0x0d,0x06,
0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x81,0x8d,
0x00,0x30,0x81,0x89,0x02,0x81,0x81,0x00,0xb8,0x52,0xda,0xc5,0x4b,0x3f,0xe5,
0x33,0x0e,0x67,0x5f,0x48,0x21,0xdc,0x7e,0xef,0x37,0x33,0xba,0xff,0xb4,0xc6,
0xdc,0xb6,0x17,0x8e,0x20,0x55,0x07,0x12,0xd2,0x7b,0x3c,0xce,0x30,0xc5,0xa7,
0x48,0x9f,0x6e,0xfe,0xb8,0xbe,0xdb,0x9f,0x9b,0x17,0x60,0x16,0xde,0xc6,0x8b,
0x47,0xd1,0x57,0x71,0x3c,0x93,0xfc,0xbd,0xec,0x44,0x32,0x3b,0xb9,0xcf,0x6b,
0x05,0x72,0xa7,0x87,0x8e,0x7e,0xd4,0x9a,0x87,0x1c,0x2f,0xb7,0x82,0x40,0xfc,
0x6a,0x80,0x83,0x68,0x28,0xce,0x84,0xf4,0x0b,0x2e,0x44,0xcb,0x53,0xac,0x85,
0x85,0xb5,0x46,0x36,0x98,0x3c,0x10,0x02,0xaa,0x02,0xbc,0x8b,0xa2,0x23,0xb2,
0xd3,0x51,0x9a,0x22,0x4a,0xe3,0xaa,0x4e,0x7c,0xda,0x38,0xcf,0x49,0x98,0x72,
0xa3,0x02,0x03,0x01,0x00,0x01,0xa3,0x23,0x30,0x21,0x30,0x1f,0x06,0x03,0x55,
0x1d,0x23,0x04,0x18,0x30,0x18,0x80,0x14,0x14,0x8c,0x16,0xbb,0xbe,0x70,0xa2,
0x28,0x89,0xa0,0x58,0xff,0x98,0xbd,0xa8,0x24,0x2b,0x8a,0xe9,0x9a,0x30,0x0d,
0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,0x00,0x03,0x81,
0x81,0x00,0x8a,0x49,0xa9,0x86,0x5e,0xc9,0x33,0x7e,0xfd,0xab,0x64,0x1f,0x6d,
0x00,0xd7,0x9b,0xec,0xd1,0x5b,0x38,0xcc,0xd6,0xf3,0xf2,0xb4,0x75,0x70,0x00,
0x82,0x9d,0x37,0x58,0xe1,0xcd,0x2c,0x61,0xb3,0x28,0xe7,0x8a,0x00,0xbe,0x6e,
0xca,0xe8,0x55,0xd5,0xad,0x3a,0xea,0xaf,0x13,0x20,0x1c,0x44,0xfc,0xb4,0xf9,
0x29,0x2b,0xdc,0x8a,0x2d,0x1b,0x27,0x9e,0xb9,0x3b,0x4a,0x71,0x9d,0x47,0x7d,
0xf7,0x92,0x6b,0x21,0x7f,0xfa,0x88,0x79,0x94,0x33,0xf6,0xdd,0x92,0x04,0x92,
0xd6,0x5e,0x0a,0x74,0xf2,0x85,0xa6,0xd5,0x3c,0x28,0xc0,0x89,0x5d,0xda,0xf3,
0xa6,0x01,0xc2,0xe9,0xa3,0xc1,0xb7,0x21,0x08,0xba,0x18,0x07,0x45,0xeb,0x77,
0x7d,0xcd,0xc6,0xe7,0x2a,0x7b,0x46,0xd2,0x3d,0xb5 };
static const BYTE rootSignedCRL[] = {
0x30,0x82,0x01,0x1f,0x30,0x81,0x89,0x02,0x01,0x01,0x30,0x0d,0x06,0x09,0x2a,
0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,0x00,0x30,0x10,0x31,0x0e,0x30,
0x0c,0x06,0x03,0x55,0x04,0x03,0x13,0x05,0x43,0x65,0x72,0x74,0x31,0x17,0x0d,
0x30,0x37,0x30,0x39,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,
0x30,0x37,0x31,0x32,0x33,0x31,0x32,0x33,0x35,0x39,0x35,0x39,0x5a,0x30,0x14,
0x30,0x12,0x02,0x01,0x01,0x17,0x0d,0x30,0x37,0x30,0x39,0x30,0x31,0x30,0x30,
0x30,0x30,0x30,0x30,0x5a,0xa0,0x2f,0x30,0x2d,0x30,0x0a,0x06,0x03,0x55,0x1d,
0x14,0x04,0x03,0x02,0x01,0x01,0x30,0x1f,0x06,0x03,0x55,0x1d,0x23,0x04,0x18,
0x30,0x18,0x80,0x14,0x14,0x8c,0x16,0xbb,0xbe,0x70,0xa2,0x28,0x89,0xa0,0x58,
0xff,0x98,0xbd,0xa8,0x24,0x2b,0x8a,0xe9,0x9a,0x30,0x0d,0x06,0x09,0x2a,0x86,
0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,0x00,0x03,0x81,0x81,0x00,0xa3,0xcf,
0x17,0x5d,0x7a,0x08,0xab,0x11,0x1a,0xbd,0x5c,0xde,0x9a,0x22,0x92,0x38,0xe6,
0x96,0xcc,0xb1,0xc5,0x42,0x86,0xa6,0xae,0xad,0xa3,0x1a,0x2b,0xa0,0xb0,0x65,
0xaa,0x9c,0xd7,0x2d,0x44,0x8c,0xae,0x61,0xc7,0x30,0x17,0x89,0x84,0x3b,0x4a,
0x8f,0x17,0x08,0x06,0x37,0x1c,0xf7,0x2d,0x4e,0x47,0x07,0x61,0x50,0xd9,0x06,
0xd1,0x46,0xed,0x0a,0xbb,0xc3,0x9b,0x36,0x0b,0xa7,0x27,0x2f,0x2b,0x55,0xce,
0x2a,0xa5,0x60,0xc6,0x53,0x28,0xe8,0xee,0xad,0x0e,0x2b,0xe8,0xd7,0x5f,0xc9,
0xa5,0xed,0xf9,0x77,0xb0,0x3c,0x81,0xcf,0xcc,0x49,0xb2,0x1a,0xc3,0xfd,0x34,
0xd5,0xbc,0xb0,0xd5,0xa5,0x9c,0x1b,0x72,0xc3,0x0f,0xa3,0xe3,0x3c,0xf0,0xc3,
0x91,0xe8,0x93,0x4f,0xd4,0x2f };

static void testVerifyRevocation(void)
{
    BOOL ret;
    CERT_REVOCATION_STATUS status = { 0 };
    PCCERT_CONTEXT certs[2];
    CERT_REVOCATION_PARA revPara = { sizeof(revPara), 0 };

    /* Crash
    ret = CertVerifyRevocation(0, 0, 0, NULL, 0, NULL, NULL);
     */
    SetLastError(0xdeadbeef);
    ret = CertVerifyRevocation(0, 0, 0, NULL, 0, NULL, &status);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %08x\n", GetLastError());
    status.cbSize = sizeof(status);
    ret = CertVerifyRevocation(0, 0, 0, NULL, 0, NULL, &status);
    ok(ret, "CertVerifyRevocation failed: %08x\n", GetLastError());
    ret = CertVerifyRevocation(0, 2, 0, NULL, 0, NULL, &status);
    ok(ret, "CertVerifyRevocation failed: %08x\n", GetLastError());
    ret = CertVerifyRevocation(2, 0, 0, NULL, 0, NULL, &status);
    ok(ret, "CertVerifyRevocation failed: %08x\n", GetLastError());
    certs[0] = CertCreateCertificateContext(X509_ASN_ENCODING, bigCert,
     sizeof(bigCert));
    SetLastError(0xdeadbeef);
    ret = CertVerifyRevocation(0, 0, 1, (void **)certs, 0, NULL, &status);
    ok(!ret && GetLastError() == CRYPT_E_NO_REVOCATION_DLL,
     "Expected CRYPT_E_NO_REVOCATION_DLL, got %08x\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CertVerifyRevocation(0, 2, 1, (void **)certs, 0, NULL, &status);
    ok(!ret && GetLastError() == CRYPT_E_NO_REVOCATION_DLL,
     "Expected CRYPT_E_NO_REVOCATION_DLL, got %08x\n", GetLastError());

    CertFreeCertificateContext(certs[0]);

    certs[0] = CertCreateCertificateContext(X509_ASN_ENCODING,
     rootWithKeySignAndCRLSign, sizeof(rootWithKeySignAndCRLSign));
    certs[1] = CertCreateCertificateContext(X509_ASN_ENCODING,
     eeCert, sizeof(eeCert));
    /* The root cert itself can't be checked for revocation */
    SetLastError(0xdeadbeef);
    ret = CertVerifyRevocation(X509_ASN_ENCODING, CERT_CONTEXT_REVOCATION_TYPE,
     1, (void **)certs, 0, NULL, &status);
    if (!ret && GetLastError() == ERROR_FILE_NOT_FOUND)
    {
        win_skip("CERT_CONTEXT_REVOCATION_TYPE unsupported, skipping\n");
        return;
    }
    ok(!ret && GetLastError() == CRYPT_E_NO_REVOCATION_CHECK,
     "expected CRYPT_E_NO_REVOCATION_CHECK, got %08x\n", GetLastError());
    ok(status.dwError == CRYPT_E_NO_REVOCATION_CHECK,
     "expected CRYPT_E_NO_REVOCATION_CHECK, got %08x\n", status.dwError);
    ok(status.dwIndex == 0, "expected index 0, got %d\n", status.dwIndex);
    /* Neither can the end cert */
    SetLastError(0xdeadbeef);
    ret = CertVerifyRevocation(X509_ASN_ENCODING, CERT_CONTEXT_REVOCATION_TYPE,
     1, (void **)&certs[1], 0, NULL, &status);
    ok(!ret && (GetLastError() == CRYPT_E_NO_REVOCATION_CHECK /* Win9x */ ||
     GetLastError() == CRYPT_E_REVOCATION_OFFLINE),
     "expected CRYPT_E_NO_REVOCATION_CHECK or CRYPT_E_REVOCATION_OFFLINE, got %08x\n",
     GetLastError());
    ok(status.dwError == CRYPT_E_NO_REVOCATION_CHECK /* Win9x */ ||
     status.dwError == CRYPT_E_REVOCATION_OFFLINE,
     "expected CRYPT_E_NO_REVOCATION_CHECK or CRYPT_E_REVOCATION_OFFLINE, got %08x\n",
     status.dwError);
    ok(status.dwIndex == 0, "expected index 0, got %d\n", status.dwIndex);
    /* Both certs together can't, either (they're not CRLs) */
    SetLastError(0xdeadbeef);
    ret = CertVerifyRevocation(X509_ASN_ENCODING, CERT_CONTEXT_REVOCATION_TYPE,
     2, (void **)certs, 0, NULL, &status);
    ok(!ret && (GetLastError() == CRYPT_E_NO_REVOCATION_CHECK ||
     GetLastError() == CRYPT_E_REVOCATION_OFFLINE /* WinME */),
     "expected CRYPT_E_NO_REVOCATION_CHECK or CRYPT_E_REVOCATION_OFFLINE, got %08x\n",
     GetLastError());
    ok(status.dwError == CRYPT_E_NO_REVOCATION_CHECK ||
     status.dwError == CRYPT_E_REVOCATION_OFFLINE /* WinME */,
     "expected CRYPT_E_NO_REVOCATION_CHECK or CRYPT_E_REVOCATION_OFFLINE, got %08x\n",
     status.dwError);
    ok(status.dwIndex == 0, "expected index 0, got %d\n", status.dwIndex);
    /* Now add a CRL to the hCrlStore */
    revPara.hCrlStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    CertAddEncodedCRLToStore(revPara.hCrlStore, X509_ASN_ENCODING,
     rootSignedCRL, sizeof(rootSignedCRL), CERT_STORE_ADD_ALWAYS, NULL);
    SetLastError(0xdeadbeef);
    ret = CertVerifyRevocation(X509_ASN_ENCODING, CERT_CONTEXT_REVOCATION_TYPE,
     2, (void **)certs, 0, &revPara, &status);
    ok(!ret && (GetLastError() == CRYPT_E_NO_REVOCATION_CHECK ||
     GetLastError() == CRYPT_E_REVOCATION_OFFLINE /* WinME */),
     "expected CRYPT_E_NO_REVOCATION_CHECK or CRYPT_E_REVOCATION_OFFLINE, got %08x\n",
     GetLastError());
    ok(status.dwError == CRYPT_E_NO_REVOCATION_CHECK ||
     status.dwError == CRYPT_E_REVOCATION_OFFLINE /* WinME */,
     "expected CRYPT_E_NO_REVOCATION_CHECK or CRYPT_E_REVOCATION_OFFLINE, got %08x\n",
     status.dwError);
    ok(status.dwIndex == 0, "expected index 0, got %d\n", status.dwIndex);
    /* Specifying CERT_VERIFY_REV_CHAIN_FLAG doesn't change things either */
    SetLastError(0xdeadbeef);
    ret = CertVerifyRevocation(X509_ASN_ENCODING, CERT_CONTEXT_REVOCATION_TYPE,
     2, (void **)certs, CERT_VERIFY_REV_CHAIN_FLAG, &revPara, &status);
    ok(!ret && GetLastError() == CRYPT_E_NO_REVOCATION_CHECK,
     "expected CRYPT_E_NO_REVOCATION_CHECK, got %08x\n", GetLastError());
    ok(status.dwError == CRYPT_E_NO_REVOCATION_CHECK,
     "expected CRYPT_E_NO_REVOCATION_CHECK, got %08x\n", status.dwError);
    ok(status.dwIndex == 0, "expected index 0, got %d\n", status.dwIndex);
    /* Again, specifying the issuer cert: no change */
    revPara.pIssuerCert = certs[0];
    SetLastError(0xdeadbeef);
    ret = CertVerifyRevocation(X509_ASN_ENCODING, CERT_CONTEXT_REVOCATION_TYPE,
     1, (void **)&certs[1], 0, &revPara, &status);
    /* Win2k thinks the cert is revoked, and it is, except the CRL is out of
     * date, hence the revocation status should be unknown.
     */
    ok(!ret && (GetLastError() == CRYPT_E_NO_REVOCATION_CHECK ||
     broken(GetLastError() == CRYPT_E_REVOKED /* Win2k */)),
     "expected CRYPT_E_NO_REVOCATION_CHECK, got %08x\n", GetLastError());
    ok(status.dwError == CRYPT_E_NO_REVOCATION_CHECK ||
     broken(status.dwError == CRYPT_E_REVOKED /* Win2k */),
     "expected CRYPT_E_NO_REVOCATION_CHECK, got %08x\n", status.dwError);
    ok(status.dwIndex == 0, "expected index 0, got %d\n", status.dwIndex);
    CertCloseStore(revPara.hCrlStore, 0);
    CertFreeCertificateContext(certs[1]);
    CertFreeCertificateContext(certs[0]);
}

static BYTE privKey[] = {
 0x07, 0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x52, 0x53, 0x41, 0x32, 0x00,
 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x79, 0x10, 0x1c, 0xd0, 0x6b, 0x10,
 0x18, 0x30, 0x94, 0x61, 0xdc, 0x0e, 0xcb, 0x96, 0x4e, 0x21, 0x3f, 0x79, 0xcd,
 0xa9, 0x17, 0x62, 0xbc, 0xbb, 0x61, 0x4c, 0xe0, 0x75, 0x38, 0x6c, 0xf3, 0xde,
 0x60, 0x86, 0x03, 0x97, 0x65, 0xeb, 0x1e, 0x6b, 0xdb, 0x53, 0x85, 0xad, 0x68,
 0x21, 0xf1, 0x5d, 0xe7, 0x1f, 0xe6, 0x53, 0xb4, 0xbb, 0x59, 0x3e, 0x14, 0x27,
 0xb1, 0x83, 0xa7, 0x3a, 0x54, 0xe2, 0x8f, 0x65, 0x8e, 0x6a, 0x4a, 0xcf, 0x3b,
 0x1f, 0x65, 0xff, 0xfe, 0xf1, 0x31, 0x3a, 0x37, 0x7a, 0x8b, 0xcb, 0xc6, 0xd4,
 0x98, 0x50, 0x36, 0x67, 0xe4, 0xa1, 0xe8, 0x7e, 0x8a, 0xc5, 0x23, 0xf2, 0x77,
 0xf5, 0x37, 0x61, 0x49, 0x72, 0x59, 0xe8, 0x3d, 0xf7, 0x60, 0xb2, 0x77, 0xca,
 0x78, 0x54, 0x6d, 0x65, 0x9e, 0x03, 0x97, 0x1b, 0x61, 0xbd, 0x0c, 0xd8, 0x06,
 0x63, 0xe2, 0xc5, 0x48, 0xef, 0xb3, 0xe2, 0x6e, 0x98, 0x7d, 0xbd, 0x4e, 0x72,
 0x91, 0xdb, 0x31, 0x57, 0xe3, 0x65, 0x3a, 0x49, 0xca, 0xec, 0xd2, 0x02, 0x4e,
 0x22, 0x7e, 0x72, 0x8e, 0xf9, 0x79, 0x84, 0x82, 0xdf, 0x7b, 0x92, 0x2d, 0xaf,
 0xc9, 0xe4, 0x33, 0xef, 0x89, 0x5c, 0x66, 0x99, 0xd8, 0x80, 0x81, 0x47, 0x2b,
 0xb1, 0x66, 0x02, 0x84, 0x59, 0x7b, 0xc3, 0xbe, 0x98, 0x45, 0x4a, 0x3d, 0xdd,
 0xea, 0x2b, 0xdf, 0x4e, 0xb4, 0x24, 0x6b, 0xec, 0xe7, 0xd9, 0x0c, 0x45, 0xb8,
 0xbe, 0xca, 0x69, 0x37, 0x92, 0x4c, 0x38, 0x6b, 0x96, 0x6d, 0xcd, 0x86, 0x67,
 0x5c, 0xea, 0x54, 0x94, 0xa4, 0xca, 0xa4, 0x02, 0xa5, 0x21, 0x4d, 0xae, 0x40,
 0x8f, 0x9d, 0x51, 0x83, 0xf2, 0x3f, 0x33, 0xc1, 0x72, 0xb4, 0x1d, 0x94, 0x6e,
 0x7d, 0xe4, 0x27, 0x3f, 0xea, 0xff, 0xe5, 0x9b, 0xa7, 0x5e, 0x55, 0x8e, 0x0d,
 0x69, 0x1c, 0x7a, 0xff, 0x81, 0x9d, 0x53, 0x52, 0x97, 0x9a, 0x76, 0x79, 0xda,
 0x93, 0x32, 0x16, 0xec, 0x69, 0x51, 0x1a, 0x4e, 0xc3, 0xf1, 0x72, 0x80, 0x78,
 0x5e, 0x66, 0x4a, 0x8d, 0x85, 0x2f, 0x3f, 0xb2, 0xa7 };

static const BYTE exportedPublicKeyBlob[] = {
0x06,0x02,0x00,0x00,0x00,0xa4,0x00,0x00,0x52,0x53,0x41,0x31,0x00,0x02,0x00,0x00,
0x01,0x00,0x01,0x00,0x79,0x10,0x1c,0xd0,0x6b,0x10,0x18,0x30,0x94,0x61,0xdc,0x0e,
0xcb,0x96,0x4e,0x21,0x3f,0x79,0xcd,0xa9,0x17,0x62,0xbc,0xbb,0x61,0x4c,0xe0,0x75,
0x38,0x6c,0xf3,0xde,0x60,0x86,0x03,0x97,0x65,0xeb,0x1e,0x6b,0xdb,0x53,0x85,0xad,
0x68,0x21,0xf1,0x5d,0xe7,0x1f,0xe6,0x53,0xb4,0xbb,0x59,0x3e,0x14,0x27,0xb1,0x83,
0xa7,0x3a,0x54,0xe2 };

static const BYTE asnEncodedPublicKey[] = {
0x30,0x48,0x02,0x41,0x00,0xe2,0x54,0x3a,0xa7,0x83,0xb1,0x27,0x14,0x3e,0x59,0xbb,
0xb4,0x53,0xe6,0x1f,0xe7,0x5d,0xf1,0x21,0x68,0xad,0x85,0x53,0xdb,0x6b,0x1e,0xeb,
0x65,0x97,0x03,0x86,0x60,0xde,0xf3,0x6c,0x38,0x75,0xe0,0x4c,0x61,0xbb,0xbc,0x62,
0x17,0xa9,0xcd,0x79,0x3f,0x21,0x4e,0x96,0xcb,0x0e,0xdc,0x61,0x94,0x30,0x18,0x10,
0x6b,0xd0,0x1c,0x10,0x79,0x02,0x03,0x01,0x00,0x01 };

static void testAcquireCertPrivateKey(void)
{
    BOOL ret;
    PCCERT_CONTEXT cert;
    HCRYPTPROV csp;
    DWORD size, keySpec;
    BOOL callerFree;
    CRYPT_KEY_PROV_INFO keyProvInfo;
    HCRYPTKEY key;
    WCHAR ms_def_prov_w[MAX_PATH];

    if (!pCryptAcquireCertificatePrivateKey)
    {
        win_skip("CryptAcquireCertificatePrivateKey() is not available\n");
        return;
    }

    lstrcpyW(ms_def_prov_w, MS_DEF_PROV_W);

    keyProvInfo.pwszContainerName = cspNameW;
    keyProvInfo.pwszProvName = ms_def_prov_w;
    keyProvInfo.dwProvType = PROV_RSA_FULL;
    keyProvInfo.dwFlags = 0;
    keyProvInfo.cProvParam = 0;
    keyProvInfo.rgProvParam = NULL;
    keyProvInfo.dwKeySpec = AT_SIGNATURE;

    pCryptAcquireContextA(NULL, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_DELETEKEYSET);

    cert = CertCreateCertificateContext(X509_ASN_ENCODING, selfSignedCert,
     sizeof(selfSignedCert));

    /* Crash
    ret = pCryptAcquireCertificatePrivateKey(NULL, 0, NULL, NULL, NULL, NULL);
    ret = pCryptAcquireCertificatePrivateKey(NULL, 0, NULL, NULL, NULL,
     &callerFree);
    ret = pCryptAcquireCertificatePrivateKey(NULL, 0, NULL, NULL, &keySpec,
     NULL);
    ret = pCryptAcquireCertificatePrivateKey(NULL, 0, NULL, &csp, NULL, NULL);
    ret = pCryptAcquireCertificatePrivateKey(NULL, 0, NULL, &csp, &keySpec,
     &callerFree);
    ret = pCryptAcquireCertificatePrivateKey(cert, 0, NULL, NULL, NULL, NULL);
     */

    /* Missing private key */
    ret = pCryptAcquireCertificatePrivateKey(cert, 0, NULL, &csp, NULL, NULL);
    ok(!ret && (GetLastError() == CRYPT_E_NO_KEY_PROPERTY || GetLastError() == NTE_BAD_PROV_TYPE /* win10 */),
     "Expected CRYPT_E_NO_KEY_PROPERTY, got %08x\n", GetLastError());
    ret = pCryptAcquireCertificatePrivateKey(cert, 0, NULL, &csp, &keySpec,
     &callerFree);
    ok(!ret && (GetLastError() == CRYPT_E_NO_KEY_PROPERTY || GetLastError() == NTE_BAD_PROV_TYPE /* win10 */),
     "Expected CRYPT_E_NO_KEY_PROPERTY, got %08x\n", GetLastError());
    CertSetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, 0,
     &keyProvInfo);
    ret = pCryptAcquireCertificatePrivateKey(cert, 0, NULL, &csp, &keySpec,
     &callerFree);
    ok(!ret && (GetLastError() == CRYPT_E_NO_KEY_PROPERTY ||
       GetLastError() == NTE_BAD_KEYSET /* win8 */ ||
       GetLastError() == NTE_BAD_PROV_TYPE /* win10 */),
     "Expected CRYPT_E_NO_KEY_PROPERTY, got %08x\n", GetLastError());

    pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_NEWKEYSET);
    ret = CryptImportKey(csp, privKey, sizeof(privKey), 0, 0, &key);
    ok(ret, "CryptImportKey failed: %08x\n", GetLastError());
    if (ret)
    {
        HCRYPTPROV certCSP;
        DWORD size;
        CERT_KEY_CONTEXT keyContext;

        /* Don't cache provider */
        ret = pCryptAcquireCertificatePrivateKey(cert, 0, NULL, &certCSP,
         &keySpec, &callerFree);
        ok(ret ||
         broken(!ret), /* win95 */
         "CryptAcquireCertificatePrivateKey failed: %08x\n",
         GetLastError());
        if (ret)
        {
            ok(callerFree, "Expected callerFree to be TRUE\n");
            CryptReleaseContext(certCSP, 0);
        }

        ret = pCryptAcquireCertificatePrivateKey(cert, 0, NULL, &certCSP,
         NULL, NULL);
        ok(ret ||
         broken(!ret), /* win95 */
         "CryptAcquireCertificatePrivateKey failed: %08x\n",
         GetLastError());
        CryptReleaseContext(certCSP, 0);

        /* Use the key prov info's caching (there shouldn't be any) */
        ret = pCryptAcquireCertificatePrivateKey(cert,
         CRYPT_ACQUIRE_USE_PROV_INFO_FLAG, NULL, &certCSP, &keySpec,
         &callerFree);
        ok(ret ||
         broken(!ret), /* win95 */
         "CryptAcquireCertificatePrivateKey failed: %08x\n",
         GetLastError());
        if (ret)
        {
            ok(callerFree, "Expected callerFree to be TRUE\n");
            CryptReleaseContext(certCSP, 0);
        }

        /* Cache it (and check that it's cached) */
        ret = pCryptAcquireCertificatePrivateKey(cert,
         CRYPT_ACQUIRE_CACHE_FLAG, NULL, &certCSP, &keySpec, &callerFree);
        ok(ret ||
         broken(!ret), /* win95 */
         "CryptAcquireCertificatePrivateKey failed: %08x\n",
         GetLastError());
        ok(!callerFree, "Expected callerFree to be FALSE\n");
        size = sizeof(keyContext);
        ret = CertGetCertificateContextProperty(cert, CERT_KEY_CONTEXT_PROP_ID,
         &keyContext, &size);
        ok(ret ||
         broken(!ret), /* win95 */
         "CertGetCertificateContextProperty failed: %08x\n",
         GetLastError());

        /* Remove the cached provider */
        CryptReleaseContext(keyContext.hCryptProv, 0);
        CertSetCertificateContextProperty(cert, CERT_KEY_CONTEXT_PROP_ID, 0,
         NULL);
        /* Allow caching via the key prov info */
        keyProvInfo.dwFlags = CERT_SET_KEY_CONTEXT_PROP_ID;
        CertSetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, 0,
         &keyProvInfo);
        /* Now use the key prov info's caching */
        ret = pCryptAcquireCertificatePrivateKey(cert,
         CRYPT_ACQUIRE_USE_PROV_INFO_FLAG, NULL, &certCSP, &keySpec,
         &callerFree);
        ok(ret ||
         broken(!ret), /* win95 */
         "CryptAcquireCertificatePrivateKey failed: %08x\n",
         GetLastError());
        ok(!callerFree, "Expected callerFree to be FALSE\n");
        size = sizeof(keyContext);
        ret = CertGetCertificateContextProperty(cert, CERT_KEY_CONTEXT_PROP_ID,
         &keyContext, &size);
        ok(ret ||
         broken(!ret), /* win95 */
         "CertGetCertificateContextProperty failed: %08x\n",
         GetLastError());
        CryptReleaseContext(certCSP, 0);

        CryptDestroyKey(key);
    }

    /* Some sanity-checking on public key exporting */
    ret = CryptImportPublicKeyInfo(csp, X509_ASN_ENCODING,
     &cert->pCertInfo->SubjectPublicKeyInfo, &key);
    ok(ret, "CryptImportPublicKeyInfo failed: %08x\n", GetLastError());
    if (ret)
    {
        ret = CryptExportKey(key, 0, PUBLICKEYBLOB, 0, NULL, &size);
        ok(ret, "CryptExportKey failed: %08x\n", GetLastError());
        if (ret)
        {
            LPBYTE buf = HeapAlloc(GetProcessHeap(), 0, size), encodedKey;

            ret = CryptExportKey(key, 0, PUBLICKEYBLOB, 0, buf, &size);
            ok(ret, "CryptExportKey failed: %08x\n", GetLastError());
            ok(size == sizeof(exportedPublicKeyBlob), "Unexpected size %d\n",
             size);
            ok(!memcmp(buf, exportedPublicKeyBlob, size), "Unexpected value\n");
            ret = pCryptEncodeObjectEx(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
             buf, CRYPT_ENCODE_ALLOC_FLAG, NULL, &encodedKey, &size);
            ok(ret, "CryptEncodeObjectEx failed: %08x\n", GetLastError());
            if (ret)
            {
                ok(size == sizeof(asnEncodedPublicKey), "Unexpected size %d\n",
                 size);
                ok(!memcmp(encodedKey, asnEncodedPublicKey, size),
                 "Unexpected value\n");
                LocalFree(encodedKey);
            }
            HeapFree(GetProcessHeap(), 0, buf);
        }
        CryptDestroyKey(key);
    }
    ret = CryptExportPublicKeyInfoEx(csp, AT_SIGNATURE, X509_ASN_ENCODING,
     NULL, 0, NULL, NULL, &size);
    ok(ret, "CryptExportPublicKeyInfoEx failed: %08x\n", GetLastError());
    if (ret)
    {
        PCERT_PUBLIC_KEY_INFO info = HeapAlloc(GetProcessHeap(), 0, size);

        ret = CryptExportPublicKeyInfoEx(csp, AT_SIGNATURE, X509_ASN_ENCODING,
         NULL, 0, NULL, info, &size);
        ok(ret, "CryptExportPublicKeyInfoEx failed: %08x\n", GetLastError());
        if (ret)
        {
            ok(info->PublicKey.cbData == sizeof(asnEncodedPublicKey),
             "Unexpected size %d\n", info->PublicKey.cbData);
            ok(!memcmp(info->PublicKey.pbData, asnEncodedPublicKey,
             info->PublicKey.cbData), "Unexpected value\n");
        }
        HeapFree(GetProcessHeap(), 0, info);
    }

    CryptReleaseContext(csp, 0);
    pCryptAcquireContextA(&csp, cspNameA, MS_DEF_PROV_A, PROV_RSA_FULL,
     CRYPT_DELETEKEYSET);

    CertFreeCertificateContext(cert);
}

static void testGetPublicKeyLength(void)
{
    static char oid_rsa_rsa[] = szOID_RSA_RSA;
    static char oid_rsa_dh[] = szOID_RSA_DH;
    static char bogusOID[] = "1.2.3";
    DWORD ret;
    CERT_PUBLIC_KEY_INFO info = { { 0 } };
    BYTE bogusKey[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    BYTE key[] = { 0x30,0x0f,0x02,0x08,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
     0x02,0x03,0x01,0x00,0x01 };

    /* Crashes
    ret = CertGetPublicKeyLength(0, NULL);
     */
    /* With an empty public key info */
    SetLastError(0xdeadbeef);
    ret = CertGetPublicKeyLength(0, &info);
    ok(ret == 0 && GetLastError() == ERROR_FILE_NOT_FOUND,
     "Expected length 0 and ERROR_FILE_NOT_FOUND, got length %d, %08x\n",
     ret, GetLastError());
    SetLastError(0xdeadbeef);
    ret = CertGetPublicKeyLength(X509_ASN_ENCODING, &info);
    ok(ret == 0 &&
     (GetLastError() == CRYPT_E_ASN1_EOD ||
      GetLastError() == OSS_BAD_ARG), /* win9x */
     "Expected length 0 and CRYPT_E_ASN1_EOD, got length %d, %08x\n",
     ret, GetLastError());
    /* With a nearly-empty public key info */
    info.Algorithm.pszObjId = oid_rsa_rsa;
    SetLastError(0xdeadbeef);
    ret = CertGetPublicKeyLength(0, &info);
    ok(ret == 0 && GetLastError() == ERROR_FILE_NOT_FOUND,
     "Expected length 0 and ERROR_FILE_NOT_FOUND, got length %d, %08x\n",
     ret, GetLastError());
    SetLastError(0xdeadbeef);
    ret = CertGetPublicKeyLength(X509_ASN_ENCODING, &info);
    ok(ret == 0 &&
     (GetLastError() == CRYPT_E_ASN1_EOD ||
      GetLastError() == OSS_BAD_ARG), /* win9x */
     "Expected length 0 and CRYPT_E_ASN1_EOD, got length %d, %08x\n",
     ret, GetLastError());
    /* With a bogus key */
    info.PublicKey.cbData = sizeof(bogusKey);
    info.PublicKey.pbData = bogusKey;
    SetLastError(0xdeadbeef);
    ret = CertGetPublicKeyLength(0, &info);
    ok(ret == 0 && GetLastError() == ERROR_FILE_NOT_FOUND,
     "Expected length 0 and ERROR_FILE_NOT_FOUND, got length %d, %08x\n",
     ret, GetLastError());
    SetLastError(0xdeadbeef);
    ret = CertGetPublicKeyLength(X509_ASN_ENCODING, &info);
    ok(ret == 0 &&
     (GetLastError() == CRYPT_E_ASN1_BADTAG ||
      GetLastError() == OSS_PDU_MISMATCH), /* win9x */
     "Expected length 0 and CRYPT_E_ASN1_BADTAGTAG, got length %d, %08x\n",
     ret, GetLastError());
    /* With a believable RSA key but a bogus OID */
    info.Algorithm.pszObjId = bogusOID;
    info.PublicKey.cbData = sizeof(key);
    info.PublicKey.pbData = key;
    SetLastError(0xdeadbeef);
    ret = CertGetPublicKeyLength(0, &info);
    ok(ret == 0 && GetLastError() == ERROR_FILE_NOT_FOUND,
     "Expected length 0 and ERROR_FILE_NOT_FOUND, got length %d, %08x\n",
     ret, GetLastError());
    SetLastError(0xdeadbeef);
    ret = CertGetPublicKeyLength(X509_ASN_ENCODING, &info);
    ok(ret == 56 || broken(ret == 0 && GetLastError() == NTE_BAD_LEN) /* Win7 */,
       "Expected length 56, got %d\n", ret);
    /* An RSA key with the DH OID */
    info.Algorithm.pszObjId = oid_rsa_dh;
    SetLastError(0xdeadbeef);
    ret = CertGetPublicKeyLength(X509_ASN_ENCODING, &info);
    ok(ret == 0 &&
     (GetLastError() == CRYPT_E_ASN1_BADTAG ||
      GetLastError() == E_INVALIDARG), /* win9x */
     "Expected length 0 and CRYPT_E_ASN1_BADTAG, got length %d, %08x\n",
     ret, GetLastError());
    /* With the RSA OID */
    info.Algorithm.pszObjId = oid_rsa_rsa;
    SetLastError(0xdeadbeef);
    ret = CertGetPublicKeyLength(X509_ASN_ENCODING, &info);
    ok(ret == 56 || broken(ret == 0 && GetLastError() == NTE_BAD_LEN) /* Win7 */,
       "Expected length 56, got %d\n", ret);
    /* With the RSA OID and a message encoding */
    info.Algorithm.pszObjId = oid_rsa_rsa;
    SetLastError(0xdeadbeef);
    ret = CertGetPublicKeyLength(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &info);
    ok(ret == 56 || broken(ret == 0 && GetLastError() == NTE_BAD_LEN) /* Win7 */,
       "Expected length 56, got %d\n", ret);
}

static void testKeyProvInfo(void)
{
    static WCHAR containerW[] = L"Wine Test Container";
    static WCHAR providerW[] = L"Hello World CSP";
    static CRYPT_KEY_PROV_PARAM param[2] = { { 0x4444, (BYTE *)"param", 6, 0x5555 }, { 0x7777, (BYTE *)"param2", 7, 0x8888 } };
    HCERTSTORE store;
    const CERT_CONTEXT *cert;
    CERT_NAME_BLOB name;
    CRYPT_KEY_PROV_INFO *info, info2;
    BOOL ret;
    DWORD size;

    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                          CERT_SYSTEM_STORE_CURRENT_USER, "My");
    ok(store != NULL, "CertOpenStore error %u\n", GetLastError());

    cert = CertCreateCertificateContext(X509_ASN_ENCODING, selfSignedCert, sizeof(selfSignedCert));
    ok(cert != NULL, "CertCreateCertificateContext error %#x\n", GetLastError());

    info2.pwszContainerName = containerW;
    info2.pwszProvName = providerW;
    info2.dwProvType = 0x12345678;
    info2.dwFlags = 0x87654321;
    info2.cProvParam = ARRAY_SIZE(param);
    info2.rgProvParam = param;
    info2.dwKeySpec = 0x11223344;
    ret = CertSetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &info2);
    ok(ret, "CertSetCertificateContextProperty error %#x\n", GetLastError());

    ret = CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &size);
    ok(ret, "CertGetCertificateContextProperty error %#x\n", GetLastError());
    info = HeapAlloc(GetProcessHeap(), 0, size);
    ret = CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, info, &size);
    ok(ret, "CertGetCertificateContextProperty error %#x\n", GetLastError());
    ok(!lstrcmpW(info->pwszContainerName, containerW), "got %s\n", wine_dbgstr_w(info->pwszContainerName));
    ok(!lstrcmpW(info->pwszProvName, providerW), "got %s\n", wine_dbgstr_w(info->pwszProvName));
    ok(info->dwProvType == 0x12345678, "got %#x\n", info->dwProvType);
    ok(info->dwFlags == 0x87654321, "got %#x\n", info->dwFlags);
    ok(info->dwKeySpec == 0x11223344, "got %#x\n", info->dwKeySpec);
    ok(info->cProvParam == 2, "got %#x\n", info->cProvParam);
    ok(info->rgProvParam != NULL, "got %p\n", info->rgProvParam);
    ok(info->rgProvParam[0].dwParam == param[0].dwParam, "got %#x\n", info->rgProvParam[0].dwParam);
    ok(info->rgProvParam[0].cbData == param[0].cbData, "got %#x\n", info->rgProvParam[0].cbData);
    ok(!memcmp(info->rgProvParam[0].pbData, param[0].pbData, param[0].cbData), "param1 mismatch\n");
    ok(info->rgProvParam[0].dwFlags == param[0].dwFlags, "got %#x\n", info->rgProvParam[1].dwFlags);
    ok(info->rgProvParam[1].dwParam == param[1].dwParam, "got %#x\n", info->rgProvParam[1].dwParam);
    ok(info->rgProvParam[1].cbData == param[1].cbData, "got %#x\n", info->rgProvParam[1].cbData);
    ok(!memcmp(info->rgProvParam[1].pbData, param[1].pbData, param[1].cbData), "param2 mismatch\n");
    ok(info->rgProvParam[1].dwFlags == param[1].dwFlags, "got %#x\n", info->rgProvParam[1].dwFlags);
    HeapFree(GetProcessHeap(), 0, info);

    ret = CertAddCertificateContextToStore(store, cert, CERT_STORE_ADD_NEW, NULL);
    ok(ret, "CertAddCertificateContextToStore error %#x\n", GetLastError());

    CertFreeCertificateContext(cert);
    CertCloseStore(store, 0);

    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                          CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG, "My");
    ok(store != NULL, "CertOpenStore error %u\n", GetLastError());

    name.pbData = subjectName;
    name.cbData = sizeof(subjectName);
    cert = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_NAME, &name, NULL);
    ok(cert != NULL, "certificate should exist in My store\n");

    ret = CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &size);
    ok(ret, "CertGetCertificateContextProperty error %#x\n", GetLastError());
    info = HeapAlloc(GetProcessHeap(), 0, size);
    ret = CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, info, &size);
    ok(ret, "CertGetCertificateContextProperty error %#x\n", GetLastError());
    ok(!lstrcmpW(info->pwszContainerName, containerW), "got %s\n", wine_dbgstr_w(info->pwszContainerName));
    ok(!lstrcmpW(info->pwszProvName, providerW), "got %s\n", wine_dbgstr_w(info->pwszProvName));
    ok(info->dwProvType == 0x12345678, "got %#x\n", info->dwProvType);
    ok(info->dwFlags == 0x87654321, "got %#x\n", info->dwFlags);
    ok(info->dwKeySpec == 0x11223344, "got %#x\n", info->dwKeySpec);
    ok(info->cProvParam == 2, "got %#x\n", info->cProvParam);
    ok(info->rgProvParam != NULL, "got %p\n", info->rgProvParam);
    ok(info->rgProvParam[0].dwParam == param[0].dwParam, "got %#x\n", info->rgProvParam[0].dwParam);
    ok(info->rgProvParam[0].cbData == param[0].cbData, "got %#x\n", info->rgProvParam[0].cbData);
    ok(!memcmp(info->rgProvParam[0].pbData, param[0].pbData, param[0].cbData), "param1 mismatch\n");
    ok(info->rgProvParam[0].dwFlags == param[0].dwFlags, "got %#x\n", info->rgProvParam[1].dwFlags);
    ok(info->rgProvParam[1].dwParam == param[1].dwParam, "got %#x\n", info->rgProvParam[1].dwParam);
    ok(info->rgProvParam[1].cbData == param[1].cbData, "got %#x\n", info->rgProvParam[1].cbData);
    ok(!memcmp(info->rgProvParam[1].pbData, param[1].pbData, param[1].cbData), "param2 mismatch\n");
    ok(info->rgProvParam[1].dwFlags == param[1].dwFlags, "got %#x\n", info->rgProvParam[1].dwFlags);
    HeapFree(GetProcessHeap(), 0, info);

    ret = CertDeleteCertificateFromStore(cert);
    ok(ret, "CertDeleteCertificateFromStore error %#x\n", GetLastError());

    CertFreeCertificateContext(cert);
    CertCloseStore(store, 0);
}

static void test_VerifySignature(void)
{
    PCCERT_CONTEXT cert;
    PCERT_SIGNED_CONTENT_INFO info;
    DWORD size;
    BOOL ret;
    HCRYPTPROV prov;
    HCRYPTKEY key;
    HCRYPTHASH hash;
    BYTE hash_value[20], *sig_value;
    DWORD hash_len, i;
    BCRYPT_KEY_HANDLE bkey;
    BCRYPT_HASH_HANDLE bhash;
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_PKCS1_PADDING_INFO pad;
    NTSTATUS status;

    cert = CertCreateCertificateContext(X509_ASN_ENCODING, selfSignedCert, sizeof(selfSignedCert));
    ok(cert != NULL, "CertCreateCertificateContext error %#x\n", GetLastError());

    /* 1. Verify certificate signature with Crypto API */
    ret = CryptVerifyCertificateSignature(0, cert->dwCertEncodingType,
            cert->pbCertEncoded, cert->cbCertEncoded, &cert->pCertInfo->SubjectPublicKeyInfo);
    ok(ret, "CryptVerifyCertificateSignature error %#x\n", GetLastError());

    /* 2. Verify certificate signature with Crypto API manually */
    ret = pCryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    ok(ret, "CryptAcquireContext error %#x\n", GetLastError());

    ret = CryptImportPublicKeyInfoEx(prov, cert->dwCertEncodingType, &cert->pCertInfo->SubjectPublicKeyInfo, 0, 0, NULL, &key);
    ok(ret, "CryptImportPublicKeyInfoEx error %#x\n", GetLastError());

    ret = CryptDecodeObjectEx(cert->dwCertEncodingType, X509_CERT,
            cert->pbCertEncoded, cert->cbCertEncoded, CRYPT_DECODE_ALLOC_FLAG, NULL, &info, &size);
    ok(ret, "CryptDecodeObjectEx error %#x\n", GetLastError());

    ret = CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash);
    ok(ret, "CryptCreateHash error %#x\n", GetLastError());

    ret = CryptHashData(hash, info->ToBeSigned.pbData, info->ToBeSigned.cbData, 0);
    ok(ret, "CryptHashData error %#x\n", GetLastError());

    ret = CryptVerifySignatureW(hash, info->Signature.pbData, info->Signature.cbData, key, NULL, 0);
    ok(ret, "CryptVerifySignature error %#x\n", GetLastError());

    CryptDestroyHash(hash);
    CryptDestroyKey(key);
    CryptReleaseContext(prov, 0);

    /* 3. Verify certificate signature with CNG */
    ret = CryptImportPublicKeyInfoEx2(cert->dwCertEncodingType, &cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &bkey);
    ok(ret, "CryptImportPublicKeyInfoEx error %#x\n", GetLastError());

    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    ok(!status, "got %#x\n", status);

    status = BCryptCreateHash(alg, &bhash, NULL, 0, NULL, 0, 0);
    ok(!status || broken(status == STATUS_INVALID_PARAMETER) /* Vista */, "got %#x\n", status);
    if (status == STATUS_INVALID_PARAMETER)
    {
        win_skip("broken BCryptCreateHash\n");
        goto done;
    }

    status = BCryptHashData(bhash, info->ToBeSigned.pbData, info->ToBeSigned.cbData, 0);
    ok(!status, "got %#x\n", status);

    status = BCryptFinishHash(bhash, hash_value, sizeof(hash_value), 0);
    ok(!status, "got %#x\n", status);
    ok(!memcmp(hash_value, selfSignedSignatureHash, sizeof(hash_value)), "got wrong hash value\n");

    status = BCryptGetProperty(bhash, BCRYPT_HASH_LENGTH, (BYTE *)&hash_len, sizeof(hash_len), &size, 0);
    ok(!status, "got %#x\n", status);
    ok(hash_len == sizeof(hash_value), "got %u\n", hash_len);

    sig_value = HeapAlloc(GetProcessHeap(), 0, info->Signature.cbData);
    for (i = 0; i < info->Signature.cbData; i++)
        sig_value[i] = info->Signature.pbData[info->Signature.cbData - i - 1];

    pad.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    status = BCryptVerifySignature(bkey, &pad, hash_value, sizeof(hash_value), sig_value, info->Signature.cbData, BCRYPT_PAD_PKCS1);
    ok(!status, "got %#x\n", status);

    HeapFree(GetProcessHeap(), 0, sig_value);
    BCryptDestroyHash(bhash);
done:
    BCryptCloseAlgorithmProvider(alg, 0);

    LocalFree(info);
    CertFreeCertificateContext(cert);
}

START_TEST(cert)
{
    init_function_pointers();

    testAddCert();
    testCertProperties();
    testCreateCert();
    testDupCert();
    testFindCert();
    testGetSubjectCert();
    testGetIssuerCert();
    testLinkCert();
    testKeyProvInfo();

    testCryptHashCert();
    testCryptHashCert2();
    testCertSigs();
    testSignAndEncodeCert();
    testCreateSelfSignCert();
    testIntendedKeyUsage();
    testKeyUsage();
    testGetValidUsages();
    testCompareCertName();
    testCompareIntegerBlob();
    testComparePublicKeyInfo();
    testHashPublicKeyInfo();
    testHashToBeSigned();
    testCompareCert();
    testVerifySubjectCert();
    testVerifyRevocation();
    testAcquireCertPrivateKey();
    testGetPublicKeyLength();
    testIsRDNAttrsInCertificateName();
    test_VerifySignature();
}
