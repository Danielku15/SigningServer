using SigningServer.Android.Math;

namespace SigningServer.Android.Security.Interfaces
{
    internal interface RSAKey
    {
        BigInteger GetModulus();
    }
}