/************************************************************************/
/* Copyright (c) 2008 Cristian Adam.

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
    claim that you wrote the original software. If you use this software
    in a product, an acknowledgment in the product documentation would be
    appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must not be
    misrepresented as being the original software.

    3. This notice may not be removed or altered from any source
    distribution.

/************************************************************************/


#ifndef INTERCEPTOR_H
#define INTERCEPTOR_H

#include "APIHook.h"

class Interceptor
{
public:
    Interceptor();

    static LONG WINAPI RegCreateKeyA(
        HKEY hKey,
        LPCSTR lpSubKey,
        PHKEY phkResult);

    static LONG WINAPI RegCreateKeyW(
        HKEY hKey,
        LPCWSTR lpSubKey,
        PHKEY phkResult);

    static LONG WINAPI RegCreateKeyExA(HKEY hKey,
        LPCSTR lpSubKey,
        DWORD Reserved,
        LPTSTR lpClass,
        DWORD dwOptions,
        REGSAM samDesired,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        PHKEY phkResult,
        LPDWORD lpdwDisposition);

    static LONG WINAPI RegCreateKeyExW(HKEY hKey,
        LPCWSTR lpSubKey,
        DWORD Reserved,
        LPTSTR lpClass,
        DWORD dwOptions,
        REGSAM samDesired,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        PHKEY phkResult,
        LPDWORD lpdwDisposition);

    static LONG WINAPI RegSetValueA(HKEY hKey,
        LPCSTR lpSubKey,
        DWORD dwType,
        LPCSTR lpData,
        DWORD cbData);

    static LONG WINAPI RegSetValueW(HKEY hKey,
        LPCWSTR lpSubKey,
        DWORD dwType,
        LPCWSTR lpData,
        DWORD cbData);

    static LONG WINAPI RegSetValueExA(HKEY hKey,
        LPCSTR lpValueName,
        DWORD Reserved,
        DWORD dwType,
        const BYTE* lpData,
        DWORD cbData);

    static LONG WINAPI RegSetValueExW(HKEY hKey,
        LPCWSTR lpValueName,
        DWORD Reserved,
        DWORD dwType,
        const BYTE* lpData,
        DWORD cbData);

    static LONG WINAPI RegOpenKeyA(HKEY hKey,
        LPCSTR lpSubKey,
        PHKEY phkResult);

    static LONG WINAPI RegOpenKeyW(HKEY hKey,
        LPCWSTR lpSubKey,
        PHKEY phkResult);

    static LONG WINAPI RegOpenKeyExA(HKEY hKey,
        LPCSTR lpSubKey,
        DWORD ulOptions,
        REGSAM samDesired,
        PHKEY phkResult);

    static LONG WINAPI RegOpenKeyExW(HKEY hKey,
        LPCWSTR lpSubKey,
        DWORD ulOptions,
        REGSAM samDesired,
        PHKEY phkResult);

    static LONG WINAPI RegCloseKey(HKEY hKey);


    template <typename T>
    static void InsertSubkeyIntoUserKeyMap(HKEY parentKey, HKEY subKey, T* subKeyName, wchar_t* funcName, bool standardKey = false);

    template <typename T>
    static void PrintKeyStats(HKEY hKey, T* keyName, wchar_t* funcName);

    template <typename T>
    static void PrintValue(wchar_t* funcName, T* valueName, DWORD type, const BYTE* pData, DWORD dataLength);

    template <typename T>
    static void AddValueToList(HKEY hKey, T* valueName, DWORD type, const BYTE* pData, DWORD dataLength);

    static std::map<HKEY, std::wstring> m_stdKeys;
    static std::map<HKEY, std::wstring> m_userKeys;

    static std::map<DWORD, std::wstring> m_regTypes;

    static bool m_doTrace;

    // Map of keys -> [name, value]
    typedef std::vector<std::pair<std::wstring, std::pair<std::wstring, std::wstring> > > ValuesListType;
    static ValuesListType m_valuesList;

    static std::auto_ptr<CAPIHook> m_RegCreateKeyA;
    static std::auto_ptr<CAPIHook> m_RegCreateKeyW;

    static std::auto_ptr<CAPIHook> m_RegCreateKeyExA;
    static std::auto_ptr<CAPIHook> m_RegCreateKeyExW;

    static std::auto_ptr<CAPIHook> m_RegSetValueA;
    static std::auto_ptr<CAPIHook> m_RegSetValueW;

    static std::auto_ptr<CAPIHook> m_RegSetValueExA;
    static std::auto_ptr<CAPIHook> m_RegSetValueExW;

    static std::auto_ptr<CAPIHook> m_RegOpenKeyA;
    static std::auto_ptr<CAPIHook> m_RegOpenKeyW;

    static std::auto_ptr<CAPIHook> m_RegOpenKeyExA;
    static std::auto_ptr<CAPIHook> m_RegOpenKeyExW;

    static std::auto_ptr<CAPIHook> m_RegCloseKey;
};
#endif // INTERCEPTOR_H