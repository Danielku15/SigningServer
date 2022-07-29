using System.Text;

namespace SigningServer.Core;

/// <summary>
/// A small helper class for hex encoding/decoding.
/// </summary>
public class HexEncoder
{
    private static readonly char[] HexDigits = "0123456789abcdef".ToCharArray();

    public static bool TryDecode(string encoded, out byte[] bytes)
    {
        try
        {
            var resultLengthBytes = (encoded.Length + 1) / 2;
            bytes = new byte[resultLengthBytes];
            var resultOffset = 0;
            var encodedCharOffset = 0;
            if ((encoded.Length % 2) != 0)
            {
                bytes[resultOffset++] = (byte)GetHexadecimalDigitValue(encoded[encodedCharOffset]);
                encodedCharOffset++;
            }

            for (var len = encoded.Length; encodedCharOffset < len; encodedCharOffset += 2)
            {
                bytes[resultOffset++] = (byte)((GetHexadecimalDigitValue(encoded[encodedCharOffset]) << 4) |
                                               GetHexadecimalDigitValue(encoded[(encodedCharOffset + 1)]));
            }

            return true;
        }
        catch
        {
            bytes = null;
            return false;
        }
    }

    private static int GetHexadecimalDigitValue(char c)
    {
        return c switch
        {
            >= 'a' and <= 'f' => (c - 'a') + 0x0a,
            >= 'A' and <= 'F' => (c - 'A') + 0x0a,
            >= '0' and <= '9' => c - '0',
            _ => throw new System.ArgumentException("Invalid hexadecimal digit at position : '" + c + "' (0x" +
                                                    ((int)c).ToString("x") + ")")
        };
    }


    public static string Encode(byte[] data)
    {
        if (data == null)
        {
            return null;
        }

        var result = new StringBuilder(data.Length * 2);
        foreach (var b in data)
        {
            var v = (int)((uint)b >> 4);
            result.Append(HexDigits[v & 0x0f]);
            result.Append(HexDigits[b & 0x0f]);
        }

        return result.ToString();
    }
}
