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
#include "ManifestWriter.h"

/*

<assembly>                          Yes
    manifestVersion             Yes
<noInheritable>                 No
<assemblyIdentity>                 Yes
    type                         Yes
    name                         Yes
    language                     No
    processorArchitecture         No
    version                     Yes
    publicKeyToken                 No
<dependency>                     No
<dependentAssembly>             No
<file>                             No
    name                         Yes
    hashalg                     No
    hash                         No
<comClass>                         No
    description                 No
    clsid                         Yes
    threadingModel                 No
    tlbid                         No
    progid                         No
    miscStatus                     No
    miscStatusIcon                 No
    miscStatusContent             No
    miscStatusDocPrint             No
    miscStatusDocPrint             No
<typelib>                         No
    tlbid                         Yes
    version                     Yes
    helpdir                     Yes
    resourceid                     No
    flags                         No
<comInterfaceExternalProxyStub>    No
    iid                         Yes
    baseInterface                 No
    numMethods                     No
    name                         No
    tlbid                         No
    proxyStubClsid32             No
<comInterfaceProxyStub>         No
    iid                         Yes
    name                         Yes
    tlbid                         No
    baseInterface                 No
    numMethods                     No
    proxyStubClsid32             No
    threadingModel                 No
<windowClass>                     No
    versioned                     No

*/

ManifestWriter::ManifestWriter(const std::wstring& assemblyName, const std::wstring& assemblyVersion, bool addArch):
CLSID(L"HKEY_CLASSES_ROOT\\CLSID\\"),
INTERFACE(L"HKEY_CLASSES_ROOT\\INTERFACE\\"),
TYPELIB(L"HKEY_CLASSES_ROOT\\TYPELIB\\"),
HKCU_SOFTWARE_CLASSES(L"HKEY_CURRENT_USER\\SOFTWARE\\CLASSES\\"),
GUID_LENGTH(38) // {00000000-0000-0000-0000-000000000000}
{
    m_data << L"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" << std::endl;
    m_data << L"<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" << std::endl;

    m_data << std::endl;
    
    m_data << L"<assemblyIdentity" << std::endl;
    m_data << L"    type=\"win32\"" << std::endl;
    m_data << L"    name=\"" << assemblyName << L"\"" << std::endl;
    m_data << L"    version=\"" << assemblyVersion << L"\"";
    if (addArch)
    {
        m_data << std::endl;
#ifdef WIN64
        m_data << L"    processorArchitecture=\"amd64\" />" << std::endl;
#else
        m_data << L"    processorArchitecture=\"x86\" />" << std::endl;
#endif
    }
    else
    {
        m_data << L" />" << std::endl;
    }
    m_data << std::endl;
}

struct CBCryptAlgHandle
{
    BCRYPT_ALG_HANDLE h = 0;
    inline operator BCRYPT_ALG_HANDLE()
    {
        return h;
    }
    inline BCRYPT_ALG_HANDLE* operator & ()
    {
        return &h;
    }
    inline ~CBCryptAlgHandle()
    {
        if (h)
            BCryptCloseAlgorithmProvider(h, 0);
    }
};

struct CBCryptHashHandle
{
    BCRYPT_HASH_HANDLE h = 0;
    inline operator BCRYPT_HASH_HANDLE()
    {
        return h;
    }
    inline BCRYPT_HASH_HANDLE* operator & ()
    {
        return &h;
    }
    inline ~CBCryptHashHandle()
    {
        if (h)
            BCryptDestroyHash(h);
    }
};

struct DigestFunctionData
{
    CBCryptHashHandle &hashHandle;
    NTSTATUS status;
};

BOOL WINAPI DigestFunction(
    DIGEST_HANDLE refdata,
    PBYTE pData,
    DWORD dwLength
)
{
    DigestFunctionData *data = reinterpret_cast<DigestFunctionData*>(refdata);
    data->status = BCryptHashData(data->hashHandle, pData, dwLength, 0);
    if (!NT_SUCCESS(data->status))
    {
        std::wcout << "Failed creating SHA256 hash: BCryptCreateHash failed with " << data->status << std::endl;
    }
    return NT_SUCCESS(data->status);
}

std::vector<unsigned char> ManifestWriter::GetBCryptHash(const std::wstring& fileName, LPCWSTR algId, bool useImageGetDigestStream)
{
    CBCryptAlgHandle algHandle;
    int status = BCryptOpenAlgorithmProvider(&algHandle, algId, nullptr, 0);
    if (!NT_SUCCESS(status))
    {
        std::wcout << "Failed getting SHA256 provider: BCryptOpenAlgorithmProvider failed with " << status << std::endl;
        return std::vector<UCHAR>();
    }
    DWORD hashObjLen;
    ULONG dummy;
    status = BCryptGetProperty(algHandle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hashObjLen), sizeof(hashObjLen), &dummy, 0);
    if (!NT_SUCCESS(status))
    {
        std::wcout << "Failed getting SHA256 provider: BCryptGetProperty(..., BCRYPT_OBJECT_LENGTH, ...) failed with " << status << std::endl;
        return std::vector<UCHAR>();
    }
    DWORD hashLen;
    status = BCryptGetProperty(algHandle, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &dummy, 0);
    if (!NT_SUCCESS(status))
    {
        std::wcout << "Failed getting SHA256 provider: BCryptGetProperty(..., BCRYPT_HASH_LENGTH, ...) failed with " << status << std::endl;
        return std::vector<UCHAR>();
    }
    std::vector<unsigned char> hashObj(hashObjLen, 0);
    CBCryptHashHandle hashHandle;
    status = BCryptCreateHash(algHandle, &hashHandle, hashObj.data(), hashObjLen, nullptr, 0, 0);
    if (!NT_SUCCESS(status))
    {
        std::wcout << "Failed creating SHA256 hash: BCryptCreateHash failed with " << status << std::endl;
        return std::vector<UCHAR>();
    }

    FILE* f = _wfopen(fileName.c_str(), L"rb");
    if (useImageGetDigestStream)
    {
        DigestFunctionData data = { hashHandle = hashHandle, status = 0 };
        if (!ImageGetDigestStream(
            reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(f))),
            CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO,
            DigestFunction,
            &data))
        {
            if (NT_SUCCESS(data.status))
            {
                std::wcout << "Failed creating SHA256 hash: ImageGetDigestStream failed with " << GetLastError() << std::endl;
            }
        }
    }
    else
    {
        std::vector<char> buf(65536, 0);
        std::ifstream fsIn(f);
        while (fsIn.good())
        {
            fsIn.read(buf.data(), buf.size());
            std::streamsize s = fsIn.gcount();
            status = BCryptHashData(hashHandle, reinterpret_cast<PUCHAR>(buf.data()), s, 0);
            if (!NT_SUCCESS(status))
            {
                std::wcout << "Failed computing SHA256 hash: BCryptHashData failed with " << status << std::endl;
                return std::vector<UCHAR>();
            }
        }
    }

    std::vector<UCHAR> hash(hashLen, 0);
    status = BCryptFinishHash(hashHandle, hash.data(), hashLen, 0);
    if (!NT_SUCCESS(status))
    {
        std::wcout << "Failed computing SHA256 hash: BCryptFinishHash failed with " << status << std::endl;
        return std::vector<UCHAR>();
    }
    return hash;
}

void ManifestWriter::AddSha256Hash(const std::wstring& fileName)
{
    std::vector<UCHAR> hash(GetBCryptHash(fileName, BCRYPT_SHA256_ALGORITHM, false));
    if (hash.empty())
        return;
    std::wstring base64Hash;
    base64Hash.resize(44, 0);
    DWORD base64HashLen = base64Hash.size() + 1;
    if (!CryptBinaryToString(hash.data(), hash.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &base64Hash[0], &base64HashLen))
    {
        std::wcout << "Failed converting SHA256 hash to base64" << std::endl;
        return;
    }
    m_data << L"    <asmv2:hash xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\">" << std::endl;
    m_data << L"        <dsig:Transforms>" << std::endl;
    m_data << L"            <dsig:Transform Algorithm=\"urn:schemas-microsoft-com:HashTransforms.Identity\" />" << std::endl;
    m_data << L"        </dsig:Transforms>" << std::endl;
    m_data << L"        <dsig:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha256\" />" << std::endl;
    m_data << L"        <dsig:DigestValue>" << base64Hash << L"</dsig:DigestValue>" << std::endl;
    m_data << L"    </asmv2:hash>" << std::endl;
}

constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
std::wstring hexStr(unsigned char *data, int len)
{
  std::wstring s(len * 2, 0);
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }
  return s;
}

void ManifestWriter::AddFileSection(const std::wstring& fileName, DigestAlgo digestAlgos)
{
    size_t lastBackslash = fileName.rfind('\\');
    size_t lastSlash = fileName.rfind('/');
    std::wstring namePart;
    if (lastBackslash != std::wstring::npos && lastSlash != std::wstring::npos)
        namePart = fileName.substr(max(lastBackslash, lastSlash) + 1);
    else if (lastBackslash != std::wstring::npos)
        namePart = fileName.substr(lastBackslash + 1);
    else if (lastSlash != std::wstring::npos)
        namePart = fileName.substr(lastSlash + 1);
    else
        namePart = fileName;

    m_data << L"<file xmlns=\"urn:schemas-microsoft-com:asm.v1\" name=\"" << namePart << L"\"";

    bool inFileTagBody = false;
    if (digestAlgos & (DigestAlgo::size | DigestAlgo::sha256))
    {
        m_data << " xmlns:asmv2=\"urn:schemas-microsoft-com:asm.v2\"";
    }
    if (digestAlgos & DigestAlgo::size)
    {
        struct _stat64 fileStat;
        _wstat64(fileName.c_str(), &fileStat);
        m_data << std::endl << "    asmv2:size=\"" << fileStat.st_size << "\"";
    }
    if (digestAlgos & DigestAlgo::sha1)
    {
        std::vector<unsigned char> hash(GetBCryptHash(fileName, BCRYPT_SHA1_ALGORITHM, true));
        if (!hash.empty())
        {
            m_data << std::endl << "    hash=\"" << hexStr(hash.data(), hash.size()) << L"\" hashalg=\"SHA1\"";
        }
    }
    if (digestAlgos & DigestAlgo::sha256)
    {
        m_data << L">" << std::endl;
        inFileTagBody = true;
        AddSha256Hash(fileName);
    }
    if (!inFileTagBody)
      m_data << L">" << std::endl;

    m_data << std::endl;
        
}

void ManifestWriter::AddComClass( const ComClass& comClass )
{
    m_data << L"    <comClass" << std::endl;
    if (!comClass.description.empty())
    {
        m_data << L"        description=\"" << comClass.description << L"\"" << std::endl;
    }
    m_data << L"        clsid=\"" << comClass.clsid << "\"";

    if (!comClass.threadingModel.empty())
    {
        m_data << std::endl;
        m_data << L"        threadingModel=\"" << comClass.threadingModel << L"\"";
    }

    if (!comClass.progid.empty())
    {
        m_data << std::endl;
        m_data << L"        progid=\"" << comClass.progid << L"\"";
    }

    if (!comClass.tlbid.empty())
    {
        m_data << std::endl;
        m_data << L"        tlbid=\"" << comClass.tlbid << L"\"";
    }
        
    m_data << " />" << std::endl;

    m_data << std::endl;
}

void ManifestWriter::AddTypeLibrary( const TypeLib& typeLib )
{
    m_data << L"    <typelib tlbid=\"" << typeLib.tlbid << L"\"" << std::endl;
    m_data << L"        version=\"" << typeLib.version << L"\"" << std::endl;
    m_data << L"        helpdir=\"" << typeLib.helpdir << L"\" />" << std::endl;

    m_data << std::endl;
}

void ManifestWriter::AddInterface(const Interface& intf)
{
    m_data << L"<comInterfaceExternalProxyStub" << std::endl;
    m_data << L"    name=\"" << intf.name << L"\"" << std::endl;
    m_data << L"    iid=\"" << intf.iid << L"\"" << std::endl;
    m_data << L"    proxyStubClsid32=\"" << intf.proxyStubClsid32 << L"\"" << std::endl;
    m_data << L"    baseInterface=\"" << intf.baseInterface << L"\"" << std::endl;

    if (!intf.tlbid.empty())
    {
        m_data << L"    tlbid=\"" << intf.tlbid << L"\"";
    }

    if (!intf.numMethods.empty())
    {
        if (!intf.tlbid.empty())
        {
            m_data << std::endl;
        }

        m_data << L"    numMethods=\"" << intf.numMethods << L"\"";
    }
    m_data << L" />" << std::endl;

    m_data << std::endl;
}

std::wstring ManifestWriter::GetRelativePath(const std::wstring& relFrom, const std::wstring& target)
{
    std::wstring absFrom(MAXSHORT, '\0');
    DWORD absFromSize = GetFullPathName(relFrom.c_str(), absFrom.size(), &absFrom[0], nullptr);
    if (!absFromSize)
    {
        std::wcout << "Getting absolute path to \"" << relFrom << "\" failed." << std::endl;
        return target;
    }
    absFrom.resize(absFromSize);
    std::wstring ret(MAX_PATH, 0);
    if (!PathRelativePathToW(
        &ret[0],
        absFrom.c_str(),
        FILE_ATTRIBUTE_NORMAL,
        target.c_str(),
        PathIsDirectoryW(target.c_str()) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL))
    {
        std::wcout << "Getting relative path to \"" << target << "\" failed." << std::endl;
        return target;
    }
    ret.resize(wcslen(ret.c_str()));
    return ret;
}

template<class _T1, class _T2>
struct pair_hash {
    inline std::size_t operator()(const std::pair<_T1, _T2> & v) const {
        size_t h = std::hash<_T1>{}(v.first);
        h ^= std::hash<_T2>{}(v.second) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

void ManifestWriter::ProcessData(const std::wstring& fileName, const Interceptor::ValuesListType& interceptedValues)
{
    Interceptor::ValuesListType::const_iterator it = interceptedValues.begin();

    std::unordered_map<std::wstring, ComClass> comClasses;
    std::unordered_map<std::pair<std::wstring, std::wstring>, TypeLib, pair_hash<std::wstring, std::wstring>> typeLibs;
    std::unordered_map<std::wstring, Interface> interfaces;

    while (it != interceptedValues.end())
    {
        std::wstring path = it->first;
        std::transform(path.begin(), path.end(), path.begin(), std::towupper);
        if (path.compare(0, HKCU_SOFTWARE_CLASSES.length(), HKCU_SOFTWARE_CLASSES) == 0)
        {
            path = L"HKEY_CLASSES_ROOT\\" + path.substr(HKCU_SOFTWARE_CLASSES.length());
        }
        if (path.compare(0, CLSID.length(), CLSID) == 0)
        {
            std::wstring clsid = path.substr(CLSID.size(), GUID_LENGTH);
            std::wstring subPath = path.length() > CLSID.size() + GUID_LENGTH ? path.substr(CLSID.size() + GUID_LENGTH + 1) : L"";

            if (subPath.compare(0, 10, L"INSTANCE\\{") == 0)
            {
                // Ignore the directshow source filter information
                ++it;
                continue;
            }
            
            ComClass &comClass = comClasses[clsid];
            comClass.clsid = clsid;
            if (subPath.empty() && it->second.first == L"(default)")
            {
                comClass.description = it->second.second;
            }
            else if (subPath.compare(L"PROGID") == 0 && it->second.first == L"(default)")
            {
                comClass.progid = it->second.second;
            }
            else if (subPath.compare(L"TYPELIB") == 0 && it->second.first == L"(default)")
            {
                comClass.tlbid = it->second.second;
            }
            else if (subPath.compare(L"INPROCSERVER32") == 0 && it->second.first == L"ThreadingModel")
            {
                comClass.threadingModel = it->second.second;
            }
        }

        if (path.compare(0, TYPELIB.length(), TYPELIB) == 0)
        {
            std::wstring tlbid = path.substr(TYPELIB.size(), GUID_LENGTH);
            std::wstring subPath = path.length() > TYPELIB.size() + GUID_LENGTH ? path.substr(TYPELIB.size() + GUID_LENGTH + 1) : L"";

            if (subPath.empty()) // no version
                continue;
            std::wstring version = subPath;
            size_t verEndPos = subPath.find(L'\\');
            std::wstring versionSubPath;
            if (verEndPos != std::wstring::npos)
            {
                versionSubPath = version.substr(verEndPos + 1);
                version.resize(verEndPos);
            }

            TypeLib &typeLib = typeLibs[{ tlbid, version }];
            typeLib.tlbid = tlbid;
            typeLib.version = version;
            if (versionSubPath.compare(L"HELPDIR") == 0 && it->second.first == L"(default)")
            {
                typeLib.helpdir = GetRelativePath(fileName, it->second.second);
            }
        }
        if (path.compare(0, INTERFACE.length(), INTERFACE) == 0)
        {
            std::wstring iid = path.substr(INTERFACE.size(), GUID_LENGTH);
            std::wstring subPath = path.length() > INTERFACE.size() + GUID_LENGTH ? path.substr(INTERFACE.size() + GUID_LENGTH + 1) : L"";

            Interface &iface = interfaces[iid];
            iface.iid = iid;
            if (subPath.empty() && it->second.first == L"(default)")
            {
                iface.name = it->second.second;
            }
            if (subPath.compare(L"PROXYSTUBCLSID32") == 0 && it->second.first == L"(default)")
            {
                iface.proxyStubClsid32 = it->second.second;
            }
            else if (subPath.compare(L"TYPELIB") == 0 && it->second.first == L"(default)")
            {
                iface.tlbid = it->second.second;
            }
            else if (subPath.compare(L"NUMMETHODS") == 0 && it->second.first == L"(default)")
            {
                iface.numMethods = it->second.second;
            }
        }

        ++it;
    }

    for (auto ccIt = comClasses.begin(); ccIt != comClasses.end(); ccIt++)
    {
        AddComClass(ccIt->second);
    }

    for (auto tlIt = typeLibs.begin(); tlIt != typeLibs.end(); tlIt++)
    {
        AddTypeLibrary(tlIt->second);
    }

    AddEndFileSection();

    for (auto ifIt = interfaces.begin(); ifIt != interfaces.end(); ifIt++)
    {
        AddInterface(ifIt->second);
    }
}

void ManifestWriter::WriteToFile(const std::wstring& outputManifestFile)
{
    m_data << L"</assembly>" << std::endl;

    FILE* file = _wfopen(outputManifestFile.c_str(), L"w, ccs=utf-8");
    if (file)
    {
        fwrite(&*m_data.str().begin(), 1, m_data.str().size() * 2, file);
        fclose(file);
    }
}

void ManifestWriter::AddEndFileSection()
{
    m_data << L"</file>" << std::endl;

    m_data << std::endl;
}

void ManifestWriter::WriteClientManifest(const std::wstring& clientFileName, const std::vector<DependencyInfo>& dependencyList)
{
    std::wstring executableFileName = clientFileName.substr(0, clientFileName.find(L".manifest"));
    std::ifstream clientFile(executableFileName.c_str(), std::ios_base::binary);

    std::wstring manifestFromExecutable;

    if (!clientFile.fail())
    {
        // Read the manifest from the end of the file
        std::vector<char> clientFileBytes;

        clientFile.seekg(0, std::ios::end);
        clientFileBytes.resize(clientFile.tellg());

        clientFile.seekg(std::ios::beg);
        clientFile.read(&*clientFileBytes.begin(), clientFileBytes.size());
     
        std::vector<char>::iterator rightToTheEnd = clientFileBytes.begin();
        std::advance(rightToTheEnd, max(0, clientFileBytes.size() - 10 * 1024));

        std::string patternBegin = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">";
        std::vector<char>::iterator posBegin =  std::search(rightToTheEnd, clientFileBytes.end(), patternBegin.begin(), patternBegin.end());

        std::string patternEnd = "</assembly>";
        std::vector<char>::iterator posEnd =  std::search(rightToTheEnd, clientFileBytes.end(), patternEnd.begin(), patternEnd.end());

        if (posBegin != clientFileBytes.end() && posEnd != clientFileBytes.end())
        {
            std::vector<char> manifest;
            std::copy(posBegin, posEnd, std::back_inserter(manifest));

            // Transform it from UTF-8 in wide chars
            int chars = ::MultiByteToWideChar(CP_UTF8, 0, &*manifest.begin(), manifest.size(), 0, 0);
            manifestFromExecutable.resize(chars);

            ::MultiByteToWideChar(CP_UTF8, 0, &*manifest.begin(), manifest.size(), &*manifestFromExecutable.begin(), chars);

            std::string::size_type pos = std::wstring::npos;
            while ((pos = manifestFromExecutable.find(L"\r\n")) != std::wstring::npos)
            {
                manifestFromExecutable.replace(pos, 2, L"\n");
            }
        }
    }


    std::wostringstream client;

    client << L"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" << std::endl;

    if (manifestFromExecutable.empty())
    {
        client << L"<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" << std::endl;

        client << std::endl;

        client << L"<assemblyIdentity" << std::endl;
        client << L"  type=\"win32\"" << std::endl;
        client << L"  name=\"client\"" << std::endl;
        client << L"  version=\"1.0.0.0\" />" << std::endl;
    }
    else
    {
        client << manifestFromExecutable;
    }

    std::vector<DependencyInfo>::const_iterator it;

    it = dependencyList.begin();
    while (it != dependencyList.end())
    {
        client << L"  <dependency>" << std::endl;
        client << L"          <dependentAssembly>" << std::endl;
        client << L"              <assemblyIdentity" << std::endl;
        client << L"                  type=\"win32\"" << std::endl;
        client << L"                  name=\"" << it->assemblyName << L"\"" << std::endl;
        client << L"                  version=\"" << it->assemblyVersion << L"\" />" << std::endl;
        client << L"          </dependentAssembly>" << std::endl;
        client << L"  </dependency>" << std::endl;

        ++it;
    }

    client << L"</assembly>" << std::endl;

    FILE* file = _wfopen(clientFileName.c_str(), L"w, ccs=utf-8");
    if (file)
    {
        fwrite(&*client.str().begin(), 1, client.str().size() * 2, file);
        fclose(file);
    }
}
