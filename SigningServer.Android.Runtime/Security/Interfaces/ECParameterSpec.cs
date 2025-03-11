using SigningServer.Android.Math;

namespace SigningServer.Android.Security.Interfaces
{
    public class ECParameterSpec
    {
        private readonly BigInteger _order;

        public ECParameterSpec(BigInteger order)
        {
            _order = order;
        }

        public BigInteger GetOrder()
        {
            return _order;
        }
    }
}
