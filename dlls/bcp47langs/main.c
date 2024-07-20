#include <hstring.h>
#include <winstring.h>

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(bcp47langs);

DWORD WINAPI GetUserLanguages(char delimiter, HSTRING *user_languages) {
    static const LPCWSTR languages = L"en-US";
    FIXME("stub, only returning en-us\n");
    WindowsCreateString(languages, wcslen(languages), user_languages);
    return 0;
}
