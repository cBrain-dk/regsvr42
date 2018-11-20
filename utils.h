/*
    Copyright (c) 2018 CBrain A/S

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software
    is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
    OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once

#include "stdafx.h"
#include "mhook.h"
#include <system_error>

template<typename TProc>
inline TProc GetProcAddressChecked(HMODULE hModule, const std::string& procName)
{
    PROC ret = GetProcAddress(hModule, procName.c_str());
    if (!ret)
        throw std::system_error(GetLastError(), std::system_category(), "GetProcAddress failed");
    return reinterpret_cast<TProc>(ret);
}

inline HMODULE GetModuleHandleChecked(const std::wstring& moduleName)
{
    HMODULE ret = GetModuleHandle(moduleName.c_str());
    if (!ret)
        throw std::system_error(GetLastError(), std::system_category(), "GetModuleHandle failed");
    return ret;
}

template <typename TProc>
class MHookFunc {
public:
    MHookFunc(const std::wstring& moduleName, const std::string& procName, TProc hookFunc)
        : MHookFunc(GetProcAddressChecked<TProc>(GetModuleHandleChecked(moduleName), procName), hookFunc)
    {}
    MHookFunc(TProc targetFunc, TProc hookFunc)
    {
        if (!Mhook_SetHook((PVOID*)&targetFunc, hookFunc))
            throw std::exception("Mhook_SetHook failed!");
        hookedFunc = targetFunc;
    }
    ~MHookFunc()
    {
        Mhook_Unhook((PVOID*)&hookedFunc);
    }
    template <typename... Args>
    std::invoke_result_t<TProc, Args...> operator () (Args... args)
    {
        return hookedFunc(std::forward<Args>(args)...);
    }
    MHookFunc(const MHookFunc&) = delete;
private:
    TProc hookedFunc;
};
