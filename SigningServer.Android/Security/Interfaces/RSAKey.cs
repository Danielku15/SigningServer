using SigningServer.Android.Math;

namespace SigningServer.Android.Security.Interfaces
{
    public interface RSAKey
    {
        BigInteger GetModulus();
    }
}