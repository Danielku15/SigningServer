using SigningServer.Android.Math;

namespace SigningServer.Android.Security.Interfaces
{
    public interface ECKey
    {
        ECParameterSpec GetParams();
    }
    
    public class ECParameterSpec
    {
        private readonly BigInteger mOrder;

        public ECParameterSpec(BigInteger order)
        {
            mOrder = order;
        }

        public BigInteger GetOrder()
        {
            return mOrder;
        }
    }
}