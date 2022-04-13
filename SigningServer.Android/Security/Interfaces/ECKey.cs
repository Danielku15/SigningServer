using SigningServer.Android.Math;

namespace SigningServer.Android.Security.Interfaces
{
    public interface ECKey
    {
        ECParameterSpec GetParams();
    }
    
    public class ECParameterSpec
    {
        public BigInteger GetOrder()
        {
            throw new System.NotImplementedException();
        }
    }

}