/*
 * Unit test suite for file functions
 *
 * Copyright 2024 Eric Pouech for CodeWeavers
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
#include <locale.h>
#include <share.h>

#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include "wine/test.h"

static void test_std_stream_buffering(void)
{
    int dup_fd, ret, pos;
    FILE *file;
    char ch;

    dup_fd = _dup(STDOUT_FILENO);
    ok(dup_fd != -1, "_dup failed\n");

    file = freopen("std_stream_test.tmp", "w", stdout);
    ok(file != NULL, "freopen failed\n");

    ret = fprintf(stdout, "test");
    pos = _telli64(STDOUT_FILENO);

    fflush(stdout);
    _dup2(dup_fd, STDOUT_FILENO);
    close(dup_fd);
    setvbuf(stdout, NULL, _IONBF, 0);

    ok(ret == 4, "fprintf(stdout) returned %d\n", ret);
    ok(!pos, "expected stdout to be buffered\n");

    dup_fd = _dup(STDERR_FILENO);
    ok(dup_fd != -1, "_dup failed\n");

    file = freopen("std_stream_test.tmp", "w", stderr);
    ok(file != NULL, "freopen failed\n");

    ret = fprintf(stderr, "test");
    ok(ret == 4, "fprintf(stderr) returned %d\n", ret);
    pos = _telli64(STDERR_FILENO);
    if (broken(!GetProcAddress(GetModuleHandleA("ucrtbase"), "__CxxFrameHandler4") && !pos))
        trace("stderr is buffered\n");
    else
        ok(pos == 4, "expected stderr to be unbuffered (%d)\n", pos);

    fflush(stderr);
    _dup2(dup_fd, STDERR_FILENO);
    close(dup_fd);

    dup_fd = _dup(STDIN_FILENO);
    ok(dup_fd != -1, "_dup failed\n");

    file = freopen("std_stream_test.tmp", "r", stdin);
    ok(file != NULL, "freopen failed\n");

    ch = 0;
    ret = fscanf(stdin, "%c", &ch);
    ok(ret == 1, "fscanf returned %d\n", ret);
    ok(ch == 't', "ch = 0x%x\n", (unsigned char)ch);
    pos = _telli64(STDIN_FILENO);
    ok(pos == 4, "pos = %d\n", pos);

    fflush(stdin);
    _dup2(dup_fd, STDIN_FILENO);
    close(dup_fd);

    ok(DeleteFileA("std_stream_test.tmp"), "DeleteFile failed\n");
}

int CDECL _get_stream_buffer_pointers(FILE*,char***,char***,int**);
static void test_iobuf_layout(void)
{
    union
    {
        FILE *f;
        struct
        {
            char* _ptr;
            char* _base;
            int   _cnt;
            int   _flag;
            int   _file;
            int   _charbuf;
            int   _bufsiz;
            char* _tmpfname;
            CRITICAL_SECTION _crit;
        } *iobuf;
    } fp;
    char *tempf, *ptr, **file_ptr, **file_base;
    int cnt, r, *file_cnt;

    tempf = _tempnam(".","wne");
    fp.f = fopen(tempf, "wb");
    ok(fp.f != NULL, "fopen failed with error: %d\n", errno);

    ok(!(fp.iobuf->_flag & 0x440), "fp.iobuf->_flag = %x\n", fp.iobuf->_flag);
    r = fprintf(fp.f, "%s", "init");
    ok(r == 4, "fprintf returned %d\n", r);
    ok(fp.iobuf->_flag & 0x40, "fp.iobuf->_flag = %x\n", fp.iobuf->_flag);
    ok(fp.iobuf->_cnt + 4 == fp.iobuf->_bufsiz, "_cnt = %d, _bufsiz = %d\n",
            fp.iobuf->_cnt, fp.iobuf->_bufsiz);

    ptr = fp.iobuf->_ptr;
    cnt = fp.iobuf->_cnt;
    r = fprintf(fp.f, "%s", "hello");
    ok(r == 5, "fprintf returned %d\n", r);
    ok(ptr + 5 == fp.iobuf->_ptr, "fp.iobuf->_ptr = %p, expected %p\n", fp.iobuf->_ptr, ptr + 5);
    ok(cnt - 5 == fp.iobuf->_cnt, "fp.iobuf->_cnt = %d, expected %d\n", fp.iobuf->_cnt, cnt - 5);
    ok(fp.iobuf->_ptr + fp.iobuf->_cnt == fp.iobuf->_base + fp.iobuf->_bufsiz,
            "_ptr = %p, _cnt = %d, _base = %p, _bufsiz  = %d\n",
            fp.iobuf->_ptr, fp.iobuf->_cnt, fp.iobuf->_base, fp.iobuf->_bufsiz);

    _get_stream_buffer_pointers(fp.f, &file_base, &file_ptr, &file_cnt);
    ok(file_base == &fp.iobuf->_base, "_base = %p, expected %p\n", file_base, &fp.iobuf->_base);
    ok(file_ptr == &fp.iobuf->_ptr, "_ptr = %p, expected %p\n", file_ptr, &fp.iobuf->_ptr);
    ok(file_cnt == &fp.iobuf->_cnt, "_cnt = %p, expected %p\n", file_cnt, &fp.iobuf->_cnt);

    r = setvbuf(fp.f, NULL, _IONBF, 0);
    ok(!r, "setvbuf returned %d\n", r);
    ok(fp.iobuf->_flag & 0x400, "fp.iobuf->_flag = %x\n", fp.iobuf->_flag);

    ok(TryEnterCriticalSection(&fp.iobuf->_crit), "TryEnterCriticalSection section returned FALSE\n");
    LeaveCriticalSection(&fp.iobuf->_crit);

    fclose(fp.f);
    unlink(tempf);
}

static void test_std_stream_open(void)
{
    FILE *f;
    int fd;

    fd = _dup(STDIN_FILENO);
    ok(fd != -1, "_dup failed\n");

    ok(!fclose(stdin), "fclose failed\n");
    f = fopen("nul", "r");
    ok(f != stdin, "f = %p, stdin =  %p\n", f, stdin);
    ok(_fileno(f) == STDIN_FILENO, "_fileno(f) = %d\n", _fileno(f));
    ok(!fclose(f), "fclose failed\n");

    f = freopen("nul", "r", stdin);
    ok(f == stdin, "f = %p, expected %p\n", f, stdin);
    ok(_fileno(f) == STDIN_FILENO, "_fileno(f) = %d\n", _fileno(f));

    _dup2(fd, STDIN_FILENO);
    close(fd);
}

static void test_fopen(void)
{
    int i;
    FILE *f;
    wchar_t wpath[MAX_PATH];
    static const struct {
        const char *loc;
        const char *path;
        int is_todo;
    } tests[] = {
        { "German.utf8",    "t\xc3\xa4\xc3\x8f\xc3\xb6\xc3\x9f.txt", TRUE },
        { "Polish.utf8",    "t\xc4\x99\xc5\x9b\xc4\x87.txt", TRUE },
        { "Turkish.utf8",   "t\xc3\x87\xc4\x9e\xc4\xb1\xc4\xb0\xc5\x9e.txt", TRUE },
        { "Arabic.utf8",    "t\xd8\xaa\xda\x86.txt", TRUE },
        { "Japanese.utf8",  "t\xe3\x82\xaf\xe3\x83\xa4.txt", TRUE },
        { "Chinese.utf8",   "t\xe4\xb8\x82\xe9\xbd\xab.txt", TRUE },
    };

    for(i=0; i<ARRAY_SIZE(tests); i++) {
        if(!setlocale(LC_ALL, tests[i].loc)) {
            win_skip("skipping locale %s\n", tests[i].loc);
            continue;
        }

        memset(wpath, 0, sizeof(wpath));
        if(!MultiByteToWideChar(CP_UTF8, 0, tests[i].path, -1, wpath, MAX_PATH)) {
            win_skip("failed to convert %s with locale %s\n", tests[i].path, tests[i].loc);
            continue;
        }

        f = _fsopen(tests[i].path, "w", SH_DENYNO);
        ok(!!f, "failed to create %s with locale %s\n", tests[i].path, tests[i].loc);
        fclose(f);

        f = _wfsopen(wpath, L"r", SH_DENYNO);
        todo_wine_if(tests[i].is_todo)
        ok(!!f, "failed to open %s with locale %s\n", tests[i].path, tests[i].loc);
        if(f) fclose(f);

        unlink(tests[i].path);
    }
    setlocale(LC_ALL, "C");
}

START_TEST(file)
{
    test_std_stream_buffering();
    test_iobuf_layout();
    test_std_stream_open();
    test_fopen();
}
