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


#include "stdafx.h"
#include "Interceptor.h"
#include <iostream>

std::auto_ptr<CAPIHook> Interceptor::m_RegCreateKeyA;
std::auto_ptr<CAPIHook> Interceptor::m_RegCreateKeyW;

std::auto_ptr<CAPIHook> Interceptor::m_RegCreateKeyExA;
std::auto_ptr<CAPIHook> Interceptor::m_RegCreateKeyExW;

std::auto_ptr<CAPIHook> Interceptor::m_RegSetValueA;
std::auto_ptr<CAPIHook> Interceptor::m_RegSetValueW;

std::auto_ptr<CAPIHook> Interceptor::m_RegSetValueExA;
std::auto_ptr<CAPIHook> Interceptor::m_RegSetValueExW;

std::auto_ptr<CAPIHook> Interceptor::m_RegOpenKeyA;
std::auto_ptr<CAPIHook> Interceptor::m_RegOpenKeyW;

std::auto_ptr<CAPIHook> Interceptor::m_RegOpenKeyExA;
std::auto_ptr<CAPIHook> Interceptor::m_RegOpenKeyExW;

std::auto_ptr<CAPIHook> Interceptor::m_RegCloseKey;

std::map<HKEY, std::wstring> Interceptor::m_stdKeys;
std::map<HKEY, std::wstring> Interceptor::m_userKeys;
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

Interceptor::Interceptor()
{
    m_valuesList.clear();
    m_userKeys.clear();
    m_stdKeys.clear();
    m_regTypes.clear();

    m_stdKeys.insert(std::make_pair(HKEY_CLASSES_ROOT, L"HKEY_CLASSES_ROOT"));
    m_stdKeys.insert(std::make_pair(HKEY_CURRENT_USER, L"HKEY_CURRENT_USER"));
    m_stdKeys.insert(std::make_pair(HKEY_LOCAL_MACHINE, L"HKEY_LOCAL_MACHINE"));
    m_stdKeys.insert(std::make_pair(HKEY_USERS, L"HKEY_USERS"));
    m_stdKeys.insert(std::make_pair(HKEY_PERFORMANCE_DATA, L"HKEY_PERFORMANCE_DATA"));
    m_stdKeys.insert(std::make_pair(HKEY_PERFORMANCE_TEXT, L"HKEY_PERFORMANCE_TEXT"));
    m_stdKeys.insert(std::make_pair(HKEY_PERFORMANCE_NLSTEXT, L"HKEY_PERFORMANCE_NLSTEXT"));
    m_stdKeys.insert(std::make_pair(HKEY_CURRENT_CONFIG, L"HKEY_CURRENT_CONFIG"));
    m_stdKeys.insert(std::make_pair(HKEY_DYN_DATA, L"HKEY_DYN_DATA"));

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

    if (!m_RegCreateKeyA.get())
    {
        m_RegCreateKeyA.reset(new CAPIHook("Advapi32.dll", "RegCreateKeyA", (PROC)RegCreateKeyA));
    }

    if (!m_RegCreateKeyW.get())
    {
        m_RegCreateKeyW.reset(new CAPIHook("Advapi32.dll", "RegCreateKeyW", (PROC)RegCreateKeyW));
    }

    if (!m_RegCreateKeyExA.get())
    {
        m_RegCreateKeyExA.reset(new CAPIHook("Advapi32.dll", "RegCreateKeyExA", (PROC)RegCreateKeyExA));
    }
    
    if (!m_RegCreateKeyExW.get())
    {
        m_RegCreateKeyExW.reset(new CAPIHook("Advapi32.dll", "RegCreateKeyExW", (PROC)RegCreateKeyExW));
    }

    if (!m_RegSetValueA.get())
    {
        m_RegSetValueA.reset(new CAPIHook("Advapi32.dll", "RegSetValueA", (PROC)RegSetValueA));
    }

    if (!m_RegSetValueW.get())
    {
        m_RegSetValueW.reset(new CAPIHook("Advapi32.dll", "RegSetValueW", (PROC)RegSetValueW));
    }

    if (!m_RegSetValueExA.get())
    {
        m_RegSetValueExA.reset(new CAPIHook("Advapi32.dll", "RegSetValueExA", (PROC)RegSetValueExA));
    }

    if (!m_RegSetValueExW.get())
    {
        m_RegSetValueExW.reset(new CAPIHook("Advapi32.dll", "RegSetValueExW", (PROC)RegSetValueExW));
    }

    if (!m_RegOpenKeyA.get())
    {
        m_RegOpenKeyA.reset(new CAPIHook("Advapi32.dll", "RegOpenKeyA", (PROC)RegOpenKeyA));
    }

    if (!m_RegOpenKeyW.get())
    {
        m_RegOpenKeyW.reset(new CAPIHook("Advapi32.dll", "RegOpenKeyW", (PROC)RegOpenKeyW));
    }

    if (!m_RegOpenKeyExA.get())
    {
        m_RegOpenKeyExA.reset(new CAPIHook("Advapi32.dll", "RegOpenKeyExA", (PROC)RegOpenKeyExA));
    }

    if (!m_RegOpenKeyExW.get())
    {
        m_RegOpenKeyExW.reset(new CAPIHook("Advapi32.dll", "RegOpenKeyExW", (PROC)RegOpenKeyExW));
    }

    if (!m_RegCloseKey.get())
    {
        m_RegCloseKey.reset(new CAPIHook("Advapi32.dll", "RegCloseKey", (PROC)RegCloseKey));
    }
}


template <typename T>
void Interceptor::InsertSubkeyIntoUserKeyMap(HKEY parentKey, HKEY subKey, T* subKeyName, wchar_t* funcName, bool fromCreateKey /*=true*/)
{
    if (subKeyName)
    {
        std::wostringstream wos;
        if (m_stdKeys.find(parentKey) != m_stdKeys.end())
        {
            wos << m_stdKeys[parentKey] << L"\\" << subKeyName;      
        }
        else if (m_userKeys.find(parentKey) != m_userKeys.end())
        {
            wos << m_userKeys[parentKey] << L"\\" << subKeyName;      
        }

        if (m_doTrace && fromCreateKey)
        {
            std::wcout << funcName << L": Adding user key: " << wos.str() << L", 0x" << std::hex << subKey << std::endl;
        }

        m_userKeys.insert(std::make_pair(subKey, wos.str()));
    }
}

template <typename T>
void Interceptor::PrintKeyStats(HKEY hKey, T* keyName, wchar_t* funcName)
{
    if (keyName)
    {
        if (m_stdKeys.find(hKey) != m_stdKeys.end())
        {
            std::wcout << funcName << L" [" << std::hex << hKey << L"]: " << m_stdKeys[hKey].c_str() << L"\\" 
                       << keyName << std::endl;
        }
        else if (m_userKeys.find(hKey) != m_userKeys.end())
        {
            std::wcout << funcName << L" [" << std::hex << hKey << L"]: " << m_userKeys[hKey].c_str() << L"\\" 
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
        result = ((PFNREGCREATEKEYA)(PROC)*m_RegCreateKeyA)(hKey, lpSubKey, phkResult);
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
        result = ((PFNREGCREATEKEYW)(PROC)*m_RegCreateKeyW)(hKey, lpSubKey, phkResult);
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
        result = ((PFNREGCREATEKEYEXA)(PROC)*m_RegCreateKeyExA)(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
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
        result = ((PFNREGCREATEKEYEXW)(PROC)*m_RegCreateKeyExW)(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
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
        result = ((PFNREGSETVALUEA)(PROC)*m_RegSetValueA)(hKey, lpSubKey, dwType, lpData, cbData);
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
        result = ((PFNREGSETVALUEW)(PROC)*m_RegSetValueW)(hKey, lpSubKey, dwType, lpData, cbData);
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
        result = ((PFNREGSETVALUEEXA)(PROC)*m_RegSetValueExA)(hKey, lpValueName, Reserved, dwType, lpData, cbData);
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
        result = ((PFNREGSETVALUEEXW)(PROC)*m_RegSetValueExW)(hKey, lpValueName, Reserved, dwType, lpData, cbData);
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
        result = ((PFNREGOPENKEYA)(PROC)*m_RegOpenKeyA)(hKey, lpSubKey, phkResult);
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
        result = ((PFNREGOPENKEYW)(PROC)*m_RegOpenKeyW)(hKey, lpSubKey, phkResult);
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
        result = ((PFNREGOPENKEYEXA)(PROC)*m_RegOpenKeyExA)(hKey, lpSubKey, ulOptions, samDesired, phkResult);
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
        result = ((PFNREGOPENKEYEXW)(PROC)*m_RegOpenKeyExW)(hKey, lpSubKey, ulOptions, samDesired, phkResult);
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
        result = ((PFNREGCLOSEKEY)(PROC)*m_RegCloseKey)(hKey);
    }
    catch (...)
    {
    }

    if (result == ERROR_SUCCESS)
    {
        if (m_userKeys.find(hKey) != m_userKeys.end())
        {
            m_userKeys.erase(hKey);
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

    m_valuesList.push_back(std::make_pair(m_userKeys[hKey], std::make_pair(wideValueName.str(), wideData.str())));
}
