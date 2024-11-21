#include <wine/test.h>
#include <winbase.h>

#include "winstring.h"
#include "msvcrt/locale.h"
#include "bcp47langs.h"

static void test_get_user_languages(void)
{
    HSTRING result;
    const WCHAR *user_languages;

    setlocale(LC_ALL, "enu");
    ok( GetUserLanguages(',', &result) == 0, "unknown return code\n" );
    user_languages = WindowsGetStringRawBuffer(result, NULL);
    ok( !lstrcmpW(user_languages, L"en-US"), "languages=%s\n", debugstr_w(user_languages) );
}

START_TEST(bcp47langs)
{
    test_get_user_languages();
}
