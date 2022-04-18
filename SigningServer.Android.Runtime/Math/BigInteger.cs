using System;

namespace SigningServer.Android.Math
{
    public class BigInteger : IComparable<BigInteger>
    {
        private readonly Org.BouncyCastle.Math.BigInteger _value;
        // ReSharper disable once InconsistentNaming
        public static readonly BigInteger ZERO = new BigInteger(Org.BouncyCastle.Math.BigInteger.Zero); 

        public BigInteger(Org.BouncyCastle.Math.BigInteger value)
        {
            _value = value;
        }

        public BigInteger(byte[] encoded)
        {
            _value = new Org.BouncyCastle.Math.BigInteger(encoded);
        }

        public int BitLength()
        {
            return _value.BitLength;
        }

        public byte[] ToByteArray()
        {
            return _value.ToByteArray();
        }

        public int CompareTo(BigInteger other)
        {
            return _value.CompareTo(other._value);
        }

        public long LongValue()
        {
            return _value.LongValue;
        }

        public static BigInteger ValueOf(long v)
        {
            return new BigInteger(Org.BouncyCastle.Math.BigInteger.ValueOf(v));
        }

        public int IntValue()
        {
            return _value.IntValue;
        }

        protected bool Equals(BigInteger other)
        {
            return Equals(_value, other._value);
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
            return (_value != null ? _value.GetHashCode() : 0);
        }

        public override string ToString()
        {
            return _value.ToString();
        }
    }
}
