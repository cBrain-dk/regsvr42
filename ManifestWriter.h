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


#ifndef MANIFEST_WRITER_H
#define MANIFEST_WRITER_H

#include "Interceptor.h"
#include "regsvr42.h"

// commdlg.h is silly and defines INTERFACE...
#undef INTERFACE

struct ComClass
{
    std::wstring clsid;
    std::wstring threadingModel;
    std::wstring description;
    std::wstring progid;
    std::wstring tlbid;
};

struct TypeLib
{
    std::wstring tlbid;
    std::wstring version;
    std::wstring helpdir;
};

struct Interface
{
    std::wstring name;
    std::wstring iid;
    std::wstring proxyStubClsid32;
    std::wstring baseInterface;
    std::wstring tlbid;
    std::wstring numMethods;

    Interface() : baseInterface(L"{00000000-0000-0000-C000-000000000046}")
    { 
    }
};

struct DependencyInfo
{
    std::wstring assemblyName;
    std::wstring assemblyVersion;

    DependencyInfo(const std::wstring& anAssemblyName, const std::wstring& anAssemblyVersion) : 
    assemblyName(anAssemblyName),
    assemblyVersion(anAssemblyVersion)
    {
    }
};


class ManifestWriter
{
public:
    ManifestWriter(const std::wstring& assemblyName, const std::wstring& assemblyVersion, bool addArch);

    void ProcessData(const std::wstring& fileName, const Interceptor::ValuesListType& interceptedValues);
    void WriteToFile(const std::wstring& outputManifestFile);

    void AddFileSection(const std::wstring& fileName, DigestAlgo digestAlgo);

    static void WriteClientManifest(const std::wstring& clientFileName, const std::vector<DependencyInfo>& dependencyList);

private:

    void AddComClass(const ComClass& comClass);
    void AddTypeLibrary(const TypeLib& typeLib);
    void AddInterface(const Interface& intf);

    std::vector<unsigned char> GetBCryptHash(const std::wstring & fileName, LPCWSTR algId, bool useImageGetDigestStream);
    void AddSha256Hash(const std::wstring& fileName);
    void AddEndFileSection();

    std::wstring GetRelativePath(const std::wstring& relFrom, const std::wstring& target);

    std::wostringstream m_data;

    const std::wstring CLSID;
    const std::wstring INTERFACE;
    const std::wstring TYPELIB;
    const std::wstring HKCU_SOFTWARE_CLASSES;

    const unsigned int GUID_LENGTH;
};

#endif // MANIFEST_WRITER_H