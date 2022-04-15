using System;

namespace SigningServer.Android.Math
{
    public readonly struct BigInteger : IComparable<BigInteger>
    {
        private readonly Org.BouncyCastle.Math.BigInteger mValue;
        public static readonly BigInteger ZERO = new BigInteger(Org.BouncyCastle.Math.BigInteger.Zero); 

        public BigInteger(Org.BouncyCastle.Math.BigInteger value)
        {
            mValue = value;
        }

        public BigInteger(sbyte[] encoded)
        {
            mValue = new Org.BouncyCastle.Math.BigInteger(encoded.AsBytes());
        }

        public int BitLength()
        {
            return mValue.BitLength;
        }

        public sbyte[] ToByteArray()
        {
            return mValue.ToByteArray().AsSBytes();
        }

        public int CompareTo(BigInteger other)
        {
            return mValue.CompareTo(other.mValue);
        }

        public long LongValue()
        {
            return mValue.LongValue;
        }

        public static BigInteger ValueOf(long v)
        {
            return new BigInteger(Org.BouncyCastle.Math.BigInteger.ValueOf(v));
        }

        public int IntValue()
        {
            return mValue.IntValue;
        }
    }
}