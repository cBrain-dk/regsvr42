/************************************************************************/
/* Copyright (c) 2018 CBrain A/S. Version modified from original version by Cristian Adam
 * Copyright (c) 2008 Cristian Adam.

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


#include "stdafx.h"
#include "Interceptor.h"
#include <iostream>

std::map<uint32_t, std::wstring> Interceptor::m_stdKeys;
std::map<uint32_t, std::wstring> Interceptor::m_userKeys;
std::map<DWORD, std::wstring> Interceptor::m_regTypes;
bool Interceptor::m_doTrace = false;
Interceptor::ValuesListType Interceptor::m_valuesList;

typedef LONG (WINAPI *PFNREGCREATEKEYA)(HKEY hKey,
                                 LPCSTR lpSubKey,
                                 PHKEY phkResult);

typedef LONG (WINAPI *PFNREGCREATEKEYW)(HKEY hKey,
                                 LPCWSTR lpSubKey,
                                 PHKEY phkResult);

typedef LONG (WINAPI *PFNREGCREATEKEYEXA)(HKEY hKey,
                            LPCSTR lpSubKey,
                            DWORD Reserved,
                            LPTSTR lpClass,
                            DWORD dwOptions,
                            REGSAM samDesired,
                            LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                            PHKEY phkResult,
                            LPDWORD lpdwDisposition);

typedef LONG (WINAPI *PFNREGCREATEKEYEXW)(HKEY hKey,
                            LPCWSTR lpSubKey,
                            DWORD Reserved,
                            LPTSTR lpClass,
                            DWORD dwOptions,
                            REGSAM samDesired,
                            LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                            PHKEY phkResult,
                            LPDWORD lpdwDisposition);

typedef LONG (WINAPI *PFNREGSETVALUEA)(HKEY hKey,
                         LPCSTR lpSubKey,
                         DWORD dwType,
                         LPCSTR lpData,
                         DWORD cbData);

typedef LONG (WINAPI *PFNREGSETVALUEW)(HKEY hKey,
                         LPCWSTR lpSubKey,
                         DWORD dwType,
                         LPCWSTR lpData,
                         DWORD cbData);

typedef LONG (WINAPI *PFNREGSETVALUEEXA)(HKEY hKey,
                           LPCSTR lpValueName,
                           DWORD Reserved,
                           DWORD dwType,
                           const BYTE* lpData,
                           DWORD cbData);

typedef LONG (WINAPI *PFNREGSETVALUEEXW)(HKEY hKey,
                                  LPCWSTR lpValueName,
                                  DWORD Reserved,
                                  DWORD dwType,
                                  const BYTE* lpData,
                                  DWORD cbData);

typedef LONG (WINAPI *PFNREGOPENKEYA)(HKEY hKey,
                               LPCSTR lpSubKey,
                               PHKEY phkResult);

typedef LONG (WINAPI *PFNREGOPENKEYW)(HKEY hKey,
                               LPCWSTR lpSubKey,
                               PHKEY phkResult);

typedef LONG (WINAPI *PFNREGOPENKEYEXA)(HKEY hKey,
                                 LPCSTR lpSubKey,
                                 DWORD ulOptions,
                                 REGSAM samDesired,
                                 PHKEY phkResult);

typedef LONG (WINAPI *PFNREGOPENKEYEXW)(HKEY hKey,
                                 LPCWSTR lpSubKey,
                                 DWORD ulOptions,
                                 REGSAM samDesired,
                                 PHKEY phkResult);

typedef LONG (WINAPI *PFNREGCLOSEKEY)(HKEY hKey);


static std::optional<MHookFunc<PFNREGCREATEKEYA>> m_RegCreateKeyA;
static std::optional<MHookFunc<PFNREGCREATEKEYW>> m_RegCreateKeyW;

static std::optional<MHookFunc<PFNREGCREATEKEYEXA>> m_RegCreateKeyExA;
static std::optional<MHookFunc<PFNREGCREATEKEYEXW>> m_RegCreateKeyExW;

static std::optional<MHookFunc<PFNREGSETVALUEA>> m_RegSetValueA;
static std::optional<MHookFunc<PFNREGSETVALUEW>> m_RegSetValueW;

static std::optional<MHookFunc<PFNREGSETVALUEEXA>> m_RegSetValueExA;
static std::optional<MHookFunc<PFNREGSETVALUEEXW>> m_RegSetValueExW;

static std::optional<MHookFunc<PFNREGOPENKEYA>> m_RegOpenKeyA;
static std::optional<MHookFunc<PFNREGOPENKEYW>> m_RegOpenKeyW;

static std::optional<MHookFunc<PFNREGOPENKEYEXA>> m_RegOpenKeyExA;
static std::optional<MHookFunc<PFNREGOPENKEYEXW>> m_RegOpenKeyExW;

static std::optional<MHookFunc<PFNREGCLOSEKEY>> m_RegCloseKey;

/* Handles on Windows are actually always 32-bit.
   There is some inconsistency in whether COM libraries zero-extends or sign-extends the special keys.
   The easiest solution is to just truncate everything down to 32-bit as that is how Windows handles
   it internally anyways.*/
inline uint32_t hkey32(HKEY key)
{
    return (uint32_t)(UINT_PTR)key;
}

Interceptor::Interceptor()
{
    m_valuesList.clear();
    m_userKeys.clear();
    m_stdKeys.clear();
    m_regTypes.clear();

    m_stdKeys.insert(std::make_pair(hkey32(HKEY_CLASSES_ROOT), L"HKEY_CLASSES_ROOT"));
    m_stdKeys.insert(std::make_pair(hkey32(HKEY_CURRENT_USER), L"HKEY_CURRENT_USER"));
    m_stdKeys.insert(std::make_pair(hkey32(HKEY_LOCAL_MACHINE), L"HKEY_LOCAL_MACHINE"));
    m_stdKeys.insert(std::make_pair(hkey32(HKEY_USERS), L"HKEY_USERS"));
    m_stdKeys.insert(std::make_pair(hkey32(HKEY_PERFORMANCE_DATA), L"HKEY_PERFORMANCE_DATA"));
    m_stdKeys.insert(std::make_pair(hkey32(HKEY_PERFORMANCE_TEXT), L"HKEY_PERFORMANCE_TEXT"));
    m_stdKeys.insert(std::make_pair(hkey32(HKEY_PERFORMANCE_NLSTEXT), L"HKEY_PERFORMANCE_NLSTEXT"));
    m_stdKeys.insert(std::make_pair(hkey32(HKEY_CURRENT_CONFIG), L"HKEY_CURRENT_CONFIG"));
    m_stdKeys.insert(std::make_pair(hkey32(HKEY_DYN_DATA), L"HKEY_DYN_DATA"));

    m_regTypes.insert(std::make_pair(REG_NONE, L"REG_NONE"));
    m_regTypes.insert(std::make_pair(REG_SZ, L"REG_SZ"));
    m_regTypes.insert(std::make_pair(REG_EXPAND_SZ, L"REG_EXPAND_SZ"));
    m_regTypes.insert(std::make_pair(REG_BINARY, L"REG_BINARY"));
    m_regTypes.insert(std::make_pair(REG_DWORD, L"REG_DWORD"));
    m_regTypes.insert(std::make_pair(REG_DWORD_LITTLE_ENDIAN, L"REG_DWORD_LITTLE_ENDIAN"));
    m_regTypes.insert(std::make_pair(REG_DWORD_BIG_ENDIAN, L"REG_DWORD_BIG_ENDIAN"));
    m_regTypes.insert(std::make_pair(REG_LINK, L"REG_LINK"));
    m_regTypes.insert(std::make_pair(REG_MULTI_SZ, L"REG_MULTI_SZ"));
    m_regTypes.insert(std::make_pair(REG_RESOURCE_LIST, L"REG_RESOURCE_LIST"));
    m_regTypes.insert(std::make_pair(REG_FULL_RESOURCE_DESCRIPTOR, L"REG_FULL_RESOURCE_DESCRIPTOR"));
    m_regTypes.insert(std::make_pair(REG_RESOURCE_REQUIREMENTS_LIST, L"REG_RESOURCE_REQUIREMENTS_LIST"));
    m_regTypes.insert(std::make_pair(REG_QWORD, L"REG_QWORD"));
    m_regTypes.insert(std::make_pair(REG_QWORD_LITTLE_ENDIAN, L"REG_QWORD_LITTLE_ENDIAN"));

    if (!m_RegCreateKeyA.has_value())
    {
        m_RegCreateKeyA.emplace(L"Advapi32.dll", "RegCreateKeyA", RegCreateKeyA);
    }

    if (!m_RegCreateKeyW.has_value())
    {
        m_RegCreateKeyW.emplace(L"Advapi32.dll", "RegCreateKeyW", RegCreateKeyW);
    }

    if (!m_RegCreateKeyExA.has_value())
    {
        m_RegCreateKeyExA.emplace(L"Advapi32.dll", "RegCreateKeyExA", RegCreateKeyExA);
    }
    
    if (!m_RegCreateKeyExW.has_value())
    {
        m_RegCreateKeyExW.emplace(L"Advapi32.dll", "RegCreateKeyExW", RegCreateKeyExW);
    }

    if (!m_RegSetValueA.has_value())
    {
        m_RegSetValueA.emplace(L"Advapi32.dll", "RegSetValueA", RegSetValueA);
    }

    if (!m_RegSetValueW.has_value())
    {
        m_RegSetValueW.emplace(L"Advapi32.dll", "RegSetValueW", RegSetValueW);
    }

    if (!m_RegSetValueExA.has_value())
    {
        m_RegSetValueExA.emplace(L"Advapi32.dll", "RegSetValueExA", RegSetValueExA);
    }

    if (!m_RegSetValueExW.has_value())
    {
        m_RegSetValueExW.emplace(L"Advapi32.dll", "RegSetValueExW", RegSetValueExW);
    }

    if (!m_RegOpenKeyA.has_value())
    {
        m_RegOpenKeyA.emplace(L"Advapi32.dll", "RegOpenKeyA", RegOpenKeyA);
    }

    if (!m_RegOpenKeyW.has_value())
    {
        m_RegOpenKeyW.emplace(L"Advapi32.dll", "RegOpenKeyW", RegOpenKeyW);
    }

    if (!m_RegOpenKeyExA.has_value())
    {
        m_RegOpenKeyExA.emplace(L"Advapi32.dll", "RegOpenKeyExA", RegOpenKeyExA);
    }

    if (!m_RegOpenKeyExW.has_value())
    {
        m_RegOpenKeyExW.emplace(L"Advapi32.dll", "RegOpenKeyExW", RegOpenKeyExW);
    }

    if (!m_RegCloseKey.has_value())
    {
        m_RegCloseKey.emplace(L"Advapi32.dll", "RegCloseKey", RegCloseKey);
    }
}


template <typename T>
void Interceptor::InsertSubkeyIntoUserKeyMap(HKEY parentKey, HKEY subKey, T* subKeyName, wchar_t* funcName, bool fromCreateKey /*=true*/)
{
    if (subKeyName)
    {
        std::wostringstream wos;
        if (m_stdKeys.find(hkey32(parentKey)) != m_stdKeys.end())
        {
            wos << m_stdKeys[hkey32(parentKey)] << L"\\" << subKeyName;      
        }
        else if (m_userKeys.find(hkey32(parentKey)) != m_userKeys.end())
        {
            wos << m_userKeys[hkey32(parentKey)] << L"\\" << subKeyName;      
        }

        if (m_doTrace && fromCreateKey)
        {
            std::wcout << funcName << L": Adding user key: " << wos.str() << L", 0x" << std::hex << subKey << std::endl;
        }

        m_userKeys.insert(std::make_pair(hkey32(subKey), wos.str()));
    }
}

template <typename T>
void Interceptor::PrintKeyStats(HKEY hKey, T* keyName, wchar_t* funcName)
{
    if (keyName)
    {
        if (m_stdKeys.find(hkey32(hKey)) != m_stdKeys.end())
        {
            std::wcout << funcName << L" [" << std::hex << hKey << L"]: " << m_stdKeys[hkey32(hKey)].c_str() << L"\\" 
                       << keyName << std::endl;
        }
        else if (m_userKeys.find(hkey32(hKey)) != m_userKeys.end())
        {
            std::wcout << funcName << L" [" << std::hex << hKey << L"]: " << m_userKeys[hkey32(hKey)].c_str() << L"\\" 
                       << keyName << std::endl;
        }
        else
        {
            std::wcout << funcName << L" [" << std::hex << hKey << L"]: Unknown HKEY " << keyName << std::endl;
        }
    }
}

LONG WINAPI Interceptor::RegCreateKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
    if (m_doTrace)
    {
        PrintKeyStats(hKey, lpSubKey, __FUNCTIONW__);
    }

    // just to have it initialized
    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegCreateKeyA.value()(hKey, lpSubKey, phkResult);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS)
    {
        InsertSubkeyIntoUserKeyMap(hKey, *phkResult, lpSubKey, __FUNCTIONW__);
    }

    return result;
}

LONG WINAPI Interceptor::RegCreateKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
    if (m_doTrace)
    {
        PrintKeyStats(hKey, lpSubKey, __FUNCTIONW__);
    }

    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegCreateKeyW.value()(hKey, lpSubKey, phkResult);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS)
    {
        InsertSubkeyIntoUserKeyMap(hKey, *phkResult, lpSubKey, __FUNCTIONW__);
    }

    return result;
}

LONG WINAPI Interceptor::RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPTSTR lpClass, 
                                         DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
                                         PHKEY phkResult, LPDWORD lpdwDisposition)
{
    if (m_doTrace)
    {
        PrintKeyStats(hKey, lpSubKey, __FUNCTIONW__);
    }

    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegCreateKeyExA.value()(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
            lpSecurityAttributes, phkResult, lpdwDisposition);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS)
    {
        InsertSubkeyIntoUserKeyMap(hKey, *phkResult, lpSubKey, __FUNCTIONW__);
    }

    return result;
}

LONG WINAPI Interceptor::RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPTSTR lpClass, 
                                         DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
                                         PHKEY phkResult, LPDWORD lpdwDisposition)
{
    if (m_doTrace)
    {
        PrintKeyStats(hKey, lpSubKey, __FUNCTIONW__);
    }

    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegCreateKeyExW.value()(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
            lpSecurityAttributes, phkResult, lpdwDisposition);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS)
    {
        InsertSubkeyIntoUserKeyMap(hKey, *phkResult, lpSubKey, __FUNCTIONW__);
    }

    return result;
}

LONG WINAPI Interceptor::RegSetValueA(HKEY hKey, LPCSTR lpSubKey, DWORD dwType, LPCSTR lpData, DWORD cbData)
{
    if (m_doTrace)
    {
        PrintValue(__FUNCTIONW__, lpSubKey ? lpSubKey : "(default)", dwType, (BYTE*)lpData, cbData);
    }


    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegSetValueA.value()(hKey, lpSubKey, dwType, lpData, cbData);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS)
    {
        AddValueToList(hKey, lpSubKey ? lpSubKey : "(default)", dwType, (BYTE*)lpData, cbData);
    }

    return result;
}

LONG WINAPI Interceptor::RegSetValueW(HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData)
{
    if (m_doTrace)
    {
        PrintValue(__FUNCTIONW__, lpSubKey ? lpSubKey : L"(default)", dwType, (BYTE*)lpData, cbData);
    }

    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegSetValueW.value()(hKey, lpSubKey, dwType, lpData, cbData);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS)
    {
        AddValueToList(hKey, lpSubKey ? lpSubKey : L"(default)", dwType, (BYTE*)lpData, cbData);
    }

    return result;
}

LONG WINAPI Interceptor::RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, 
                                        DWORD cbData)
{
    if (m_doTrace)
    {
        PrintValue(__FUNCTIONW__, lpValueName ? lpValueName : "(default)", dwType,lpData, cbData);
    }

    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegSetValueExA.value()(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS)
    {
        AddValueToList(hKey, lpValueName ? lpValueName : "(default)", dwType, lpData, cbData);
    }

    return result;
}

LONG WINAPI Interceptor::RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, 
                                        DWORD cbData)
{
    if (m_doTrace)
    {
        PrintValue(__FUNCTIONW__, lpValueName ? lpValueName : L"(default)", dwType, lpData, cbData);
    }

    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegSetValueExW.value()(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS)
    {
        AddValueToList(hKey, lpValueName ? lpValueName : L"(default)", dwType, lpData, cbData);
    }

    return result;
}

LONG WINAPI Interceptor::RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegOpenKeyA.value()(hKey, lpSubKey, phkResult);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS && lpSubKey)
    {
        InsertSubkeyIntoUserKeyMap(hKey, *phkResult, lpSubKey, __FUNCTIONW__, false);
    }

    return result;
}

LONG WINAPI Interceptor::RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegOpenKeyW.value()(hKey, lpSubKey, phkResult);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS && lpSubKey)
    {
        InsertSubkeyIntoUserKeyMap(hKey, *phkResult, lpSubKey, __FUNCTIONW__, false);
    }

    return result;
}

LONG WINAPI Interceptor::RegOpenKeyExA( HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult )
{
    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegOpenKeyExA.value()(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS && lpSubKey)
    {
        InsertSubkeyIntoUserKeyMap(hKey, *phkResult, lpSubKey, __FUNCTIONW__, false);
    }

    return result;
}

LONG WINAPI Interceptor::RegOpenKeyExW( HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult )
{
    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegOpenKeyExW.value()(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS && lpSubKey)
    {
        InsertSubkeyIntoUserKeyMap(hKey, *phkResult, lpSubKey, __FUNCTIONW__, false);
    }

    return result;
}

LONG WINAPI Interceptor::RegCloseKey(HKEY hKey)
{
    LONG result = ERROR_ARENA_TRASHED;
    try
    {
        result = m_RegCloseKey.value()(hKey);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS)
    {
        if (m_userKeys.find(hkey32(hKey)) != m_userKeys.end())
        {
            m_userKeys.erase(hkey32(hKey));
        }
    }

    return result;
}

template <typename T>
void Interceptor::PrintValue(wchar_t* funcName, T* pValueName, DWORD type, const BYTE* pData, DWORD dataLength)
{
    std::wcout << funcName << L" [" << m_regTypes[type] <<  L"] name: " << pValueName;

    if (type == REG_SZ)
    {
        std::wcout << L", value: " << reinterpret_cast<T*>(pData) << std::endl;
    }
    else if (type == REG_DWORD)
    {
        std::wcout << L", value: 0x" << std::hex << *reinterpret_cast<const DWORD*>(pData) << std::endl;
    }
    else
    {
        std::wcout << std::endl;
    }
}

template <typename T>
void Interceptor::AddValueToList(HKEY hKey, T* valueName, DWORD type, const BYTE* pData, DWORD dataLength)
{
    std::wostringstream wideValueName;
    wideValueName << valueName;

    std::wostringstream wideData;
    if (type == REG_SZ)
    {
        wideData << reinterpret_cast<T*>(pData);
    }
    else if (type == REG_DWORD)
    {
        wideData << *reinterpret_cast<const DWORD*>(pData);
    }
    else
    {
        std::wcout << L"Type: " << m_regTypes[type] << L", name: " << valueName << L" not used!" << std::endl;
    }

    if (wideValueName.str().empty())
    {
        wideValueName << L"(default)";
    }

    m_valuesList.push_back(std::make_pair(m_userKeys[hkey32(hKey)], std::make_pair(wideValueName.str(), wideData.str())));
}
