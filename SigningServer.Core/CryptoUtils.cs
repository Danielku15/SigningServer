using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace SigningServer.Core;

public static class CryptoUtils
{
    private static readonly Dictionary<string, Func<HashAlgorithm>> HashAlgorithms =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["SHA1"] = SHA1.Create,
            ["MD5"] = MD5.Create,
            ["SHA256"] = SHA256.Create,
            ["SHA384"] = SHA384.Create,
            ["SHA512"] = SHA512.Create,
            ["SHA3_256"] = SHA3_256.Create,
            ["SHA3_384"] = SHA3_384.Create,
            ["SHA3_512"] = SHA3_512.Create
        };

    public static HashAlgorithm? CreateHashAlgorithmFromName(string name)
    {
        return HashAlgorithms.TryGetValue(name, out var factory) ? factory() : null;
    }
}
