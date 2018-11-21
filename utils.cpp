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

#include "utils.h"

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

std::vector<unsigned char> GetBCryptHash(const std::wstring& fileName, LPCWSTR algId, bool useImageGetDigestStream)
{
    CBCryptAlgHandle algHandle;
    int status = BCryptOpenAlgorithmProvider(&algHandle, algId, nullptr, 0);
    if (!NT_SUCCESS(status))
    {
        std::wcout << L"Failed getting " << algId << L" provider: BCryptOpenAlgorithmProvider failed with " << status << std::endl;
        return std::vector<UCHAR>();
    }
    DWORD hashObjLen;
    ULONG dummy;
    status = BCryptGetProperty(algHandle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hashObjLen), sizeof(hashObjLen), &dummy, 0);
    if (!NT_SUCCESS(status))
    {
        std::wcout << L"Failed getting " << algId << L" provider: BCryptGetProperty(..., BCRYPT_OBJECT_LENGTH, ...) failed with " << status << std::endl;
        return std::vector<UCHAR>();
    }
    DWORD hashLen;
    status = BCryptGetProperty(algHandle, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &dummy, 0);
    if (!NT_SUCCESS(status))
    {
        std::wcout << L"Failed getting " << algId << L" provider: BCryptGetProperty(..., BCRYPT_HASH_LENGTH, ...) failed with " << status << std::endl;
        return std::vector<UCHAR>();
    }
    std::vector<unsigned char> hashObj(hashObjLen, 0);
    CBCryptHashHandle hashHandle;
    status = BCryptCreateHash(algHandle, &hashHandle, hashObj.data(), hashObjLen, nullptr, 0, 0);
    if (!NT_SUCCESS(status))
    {
        std::wcout << L"Failed creating " << algId << L" hash: BCryptCreateHash failed with " << status << std::endl;
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
                std::wcout << L"Failed creating " << algId << L" hash: ImageGetDigestStream failed with " << GetLastError() << std::endl;
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
                std::wcout << L"Failed computing " << algId << L" hash: BCryptHashData failed with " << status << std::endl;
                return std::vector<UCHAR>();
            }
        }
    }

    std::vector<UCHAR> hash(hashLen, 0);
    status = BCryptFinishHash(hashHandle, hash.data(), hashLen, 0);
    if (!NT_SUCCESS(status))
    {
        std::wcout << L"Failed computing " << algId << L" hash: BCryptFinishHash failed with " << status << std::endl;
        return std::vector<UCHAR>();
    }
    return hash;
}

constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
std::wstring HexStr(unsigned char *data, int len)
{
  std::wstring s(len * 2, 0);
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }
  return s;
}
