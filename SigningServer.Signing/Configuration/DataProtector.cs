using System;
using System.IO;
using System.Security.Cryptography;

namespace SigningServer.Signing.Configuration;

/// <summary>
/// A utility class to protect/unprotect any strings using the data projection API.
/// </summary>
public class DataProtector
{
    public static string ProtectData(string raw)
    {
        var ms = new MemoryStream();
        var writer = new BinaryWriter(ms);
        writer.Write(raw);
        writer.Flush();
        var padding = 16 - (ms.Length % 16);
        if (padding > 0)
        {
            writer.Write(new byte[padding]);
        }

        var data = ms.ToArray();
        var encrypted = ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(encrypted);
    }

    public static string UnprotectData(string encoded)
    {
        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(encoded);
        }
        catch
        {
            // no base64 encoded text -> plain
            return encoded;
        }

        var decrypted = ProtectedData.Unprotect(raw, null, DataProtectionScope.CurrentUser);
        var ms = new MemoryStream(decrypted);
        var reader = new BinaryReader(ms);
        return reader.ReadString();
    }
}
