using System.Security.Cryptography;

namespace JwtGenerator.Security;

public static class Base64Url
{
    public static string Encode(byte[] bytes)
    {
        var s = Convert.ToBase64String(bytes);
        s = s.TrimEnd('=');
        s = s.Replace('+', '-');
        s = s.Replace('/', '_');
        return s;
    }

    public static string EncodeBigEndian(ReadOnlySpan<byte> bigEndianUnsigned)
    {
        var trimmed = bigEndianUnsigned;
        while (trimmed.Length > 1 && trimmed[0] == 0x00)
        {
            trimmed = trimmed[1..];
        }

        return Encode(trimmed.ToArray());
    }

    public static string EncodeBigInteger(System.Numerics.BigInteger value)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        return Encode(bytes);
    }

    public static byte[] RandomBytes(int size)
    {
        var bytes = new byte[size];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }
}
