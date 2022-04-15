using SigningServer.Android.Math;

namespace SigningServer.Android.Security.Interfaces
{
    public interface ECKey
    {
        ECParameterSpec GetParams();
    }
    
    public interface ECParameterSpec
    {
        BigInteger GetOrder();
    }
}