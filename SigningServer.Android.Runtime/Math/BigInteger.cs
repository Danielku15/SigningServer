using System;

namespace SigningServer.Android.Math
{
    public class BigInteger : IComparable<BigInteger>
    {
        private readonly Org.BouncyCastle.Math.BigInteger mValue;
        public static readonly BigInteger ZERO = new BigInteger(Org.BouncyCastle.Math.BigInteger.Zero); 

        public BigInteger(Org.BouncyCastle.Math.BigInteger value)
        {
            mValue = value;
        }

        public BigInteger(byte[] encoded)
        {
            mValue = new Org.BouncyCastle.Math.BigInteger(encoded);
        }

        public int BitLength()
        {
            return mValue.BitLength;
        }

        public byte[] ToByteArray()
        {
            return mValue.ToByteArray();
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

        protected bool Equals(BigInteger other)
        {
            return Equals(mValue, other.mValue);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((BigInteger)obj);
        }

        public override int GetHashCode()
        {
            return (mValue != null ? mValue.GetHashCode() : 0);
        }

        public override string ToString()
        {
            return mValue.ToString();
        }
    }
}