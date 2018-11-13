#pragma once

enum DigestAlgo : int 
{ 
    none = 0,
    size = 1,
    sha1 = 2,
    sha256 = 4
};

inline DigestAlgo operator |= (DigestAlgo &lhs, DigestAlgo rhs)
{
    lhs = static_cast<DigestAlgo>(lhs | rhs);
    return lhs;
}
