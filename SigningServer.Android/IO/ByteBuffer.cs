namespace SigningServer.Android.IO
{
    public abstract class ByteBuffer : Buffer
    {
        protected internal byte[] mRaw;
        protected int mOffset;

        // ReSharper disable once UnusedParameter.Global
        public ByteBuffer Order(ByteOrder byteOrder)
        {
            return this;
        }

        public abstract ByteBuffer Slice();
        public abstract byte Get();
        public abstract byte Get(int i);

        protected ByteBuffer(int mark, int pos, int lim, int cap, byte[] hb, int offset)
            : base(mark, pos, lim, cap)
        {
            mRaw = hb;
            mOffset = offset;
        }

        public abstract long GetLong();
        public abstract short GetShort();
        public abstract int GetInt();
        public abstract long GetLong(int offset);
        public abstract void Get(byte[] dst);
        public abstract int GetInt(int i);
        public abstract short GetShort(int i);
        public abstract void Get(byte[] dst, int offset, int length);

        public ByteBuffer AsReadOnlyBuffer()
        {
            return this;
        }

        public static ByteBuffer Allocate(int capacity)
        {
            return new HeapByteBuffer(capacity, capacity);
        }

        public bool HasArray()
        {
            return mRaw != null;
        }

        public byte[] Array()
        {
            return mRaw;
        }

        public int ArrayOffset()
        {
            return mOffset;
        }

        public abstract ByteOrder Order();
        public abstract void Put(ByteBuffer src);


        public void Put(byte[] src)
        {
            Put(src, 0, src.Length);
        }

        public abstract void Put(byte[] src, int offset, int length);
        public abstract void PutShort(int offset, short value);
        public abstract void PutLong(long value);
        public abstract void PutInt(int offset, int value);
        public abstract void PutShort(short value);
        public abstract ByteBuffer PutInt(int value);

        public static ByteBuffer Wrap(byte[] src)
        {
            return new HeapByteBuffer(src, 0, src.Length);
        }

        public static ByteBuffer Wrap(byte[] src, int offset, int length)
        {
            return new HeapByteBuffer(src, offset, length);
        }

        public static ByteBuffer AllocateDirect(int size)
        {
            return Allocate(size);
        }

        public abstract ByteBuffer Duplicate();
        public abstract void Put(byte x);

        public int CompareTo(ByteBuffer that)
        {
            int thisPos = Position();
            int thisRem = Limit() - thisPos;
            int thatPos = that.Position();
            int thatRem = that.Limit() - thatPos;
            int length = System.Math.Min(thisRem, thatRem);
            if (length < 0)
                return -1;
            int i = Mismatch(this, thisPos,
                that, thatPos,
                length);
            if (i >= 0)
            {
                return Get(thisPos + i).CompareTo(that.Get(thatPos + i));
            }

            return thisRem - thatRem;
        }
        
        
        private int Mismatch(ByteBuffer a, int aOff, ByteBuffer b, int bOff, int length)
        {
            for (int i = 0; i < length; i++)
            {
                if (a.Get(aOff + i) != b.Get(bOff + i))
                {
                    return i;
                }
            }

            return -1;
        }
    }
}