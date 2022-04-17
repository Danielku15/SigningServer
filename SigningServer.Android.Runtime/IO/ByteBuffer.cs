using System;

namespace SigningServer.Android.IO
{
    public class ByteBuffer
    {
        private byte[] mRaw;
        private int mOffset;
        private readonly int mCapacity;
        private int mMark = -1;
        private int mPosition;
        private int mLimit;

        public int Capacity()
        {
            return mCapacity;
        }

        public int Limit()
        {
            return mLimit;
        }

        private ByteBuffer(byte[] buf,
            int mark, int pos, int lim, int cap,
            int off)
            : this(mark, pos, lim, cap, buf, off)
        {
        }

        internal ByteBuffer(int cap, int lim) : this(-1, 0, lim, cap, new byte[cap], 0)
        {
        }

        internal ByteBuffer(byte[] buf, int off, int len)
            : this(-1, off, off + len, buf.Length, buf, 0)
        {
        }

        protected ByteBuffer(int mark, int pos, int lim, int cap, byte[] hb, int offset)
            : this(mark, pos, lim, cap)
        {
            mRaw = hb;
            mOffset = offset;
        }

        protected ByteBuffer(int mark, int pos, int lim, int cap)
        {
            if (cap < 0)
            {
                throw CreateCapacityException(cap);
            }

            mCapacity = cap;
            Limit(lim);
            Position(pos);
            if (mark >= 0)
            {
                if (mark > pos)
                    throw new ArgumentException("mark > position: ("
                                                + mark + " > " + pos + ")");
                mMark = mark;
            }
        }

        public void Limit(int newLimit)
        {
            if (newLimit > mCapacity | newLimit < 0)
                throw CreateLimitException(newLimit);
            mLimit = newLimit;
            if (mPosition > newLimit) mPosition = newLimit;
            if (mMark > newLimit) mMark = -1;
        }

        public int Position()
        {
            return mPosition;
        }

        public void Position(int newPosition)
        {
            if (newPosition > mLimit | newPosition < 0)
                throw CreatePositionException(newPosition);
            if (mMark > newPosition) mMark = -1;
            mPosition = newPosition;
        }

        private ArgumentException CreatePositionException(int newPosition)
        {
            String msg;

            if (newPosition > mLimit)
            {
                msg = "newPosition > limit: (" + newPosition + " > " + mLimit + ")";
            }
            else
            {
                // assume negative
                msg = "newPosition < 0: (" + newPosition + " < 0)";
            }

            return new ArgumentException(msg);
        }

        private ArgumentException CreateLimitException(int newLimit)
        {
            String msg = null;

            if (newLimit > mCapacity)
            {
                msg = "newLimit > capacity: (" + newLimit + " > " + mCapacity + ")";
            }
            else
            {
                // assume negative
                msg = "newLimit < 0: (" + newLimit + " < 0)";
            }

            return new ArgumentException(msg);
        }

        static ArgumentException CreateCapacityException(int capacity)
        {
            return new ArgumentException("capacity < 0: ("
                                         + capacity + " < 0)");
        }


        public int Remaining()
        {
            var rem = mLimit - mPosition;
            return rem > 0 ? rem : 0;
        }


        public int NextGetIndex()
        {
            var p = mPosition;
            if (p >= mLimit)
            {
                throw new BufferUnderflowException();
            }

            mPosition = p + 1;
            return p;
        }

        protected int CheckIndex(int i)
        {
            if (i < 0 || i >= mLimit)
            {
                throw new IndexOutOfRangeException();
            }

            return i;
        }

        protected int NextGetIndex(int nb)
        {
            var p = mPosition;
            if (mLimit - p < nb)
            {
                throw new BufferUnderflowException();
            }

            mPosition = p + nb;
            return p;
        }

        protected int CheckIndex(int i, int nb)
        {
            if (i < 0 || (nb > mLimit - i))
            {
                throw new IndexOutOfRangeException();
            }

            return i;
        }

        public void Flip()
        {
            mLimit = mPosition;
            mPosition = 0;
            mMark = 0;
        }

        public bool HasRemaining()
        {
            return mPosition < mLimit;
        }

        public void Rewind()
        {
            mPosition = 0;
            mMark = -1;
        }

        public void Clear()
        {
            mPosition = 0;
            mLimit = mCapacity;
            mMark = -1;
        }

        public void Mark()
        {
            mMark = mPosition;
        }

        public void Reset()
        {
            var m = mMark;
            if (m < 0)
            {
                throw new InvalidOperationException();
            }

            mPosition = m;
        }

        protected int NextPutIndex()
        {
            int p = mPosition;
            if (p >= mLimit)
            {
                throw new BufferOverflowException();
            }

            mPosition = p + 1;
            return p;
        }

        // ReSharper disable once UnusedParameter.Global
        public ByteBuffer Order(ByteOrder byteOrder)
        {
            return this;
        }

        public ByteBuffer Slice()
        {
            int pos = Position();
            int lim = Limit();
            int rem = (pos <= lim ? lim - pos : 0);
            return new ByteBuffer(mRaw,
                -1,
                0,
                rem,
                rem,
                pos + mOffset);
        }

        public byte Get()
        {
            return mRaw[Index(NextGetIndex())];
        }

        public byte Get(int i)
        {
            return mRaw[Index(CheckIndex(i))];
        }

        private int Index(int i)
        {
            return i + mOffset;
        }

        public long GetLong()
        {
            return BitConverter.ToInt64(mRaw, Index(NextGetIndex(8)));
        }

        public short GetShort()
        {
            return BitConverter.ToInt16(mRaw, Index(NextGetIndex(2)));
        }

        public int GetInt()
        {
            return BitConverter.ToInt32(mRaw, Index(NextGetIndex(4)));
        }

        public long GetLong(int offset)
        {
            return BitConverter.ToInt64(mRaw, Index(CheckIndex(offset, 8)));
        }

        public void Get(byte[] dst)
        {
            Get(dst, 0, dst.Length);
        }

        public int GetInt(int i)
        {
            return BitConverter.ToInt32(mRaw, Index(CheckIndex(i, 4)));
        }

        public short GetShort(int i)
        {
            return BitConverter.ToInt16(mRaw, Index(CheckIndex(i, 2)));
        }


        public void Get(byte[] dst, int offset, int length)
        {
            int pos = Position();
            if (length > Limit() - pos)
            {
                throw new BufferUnderflowException();
            }

            System.Buffer.BlockCopy(mRaw, Index(pos), dst, offset, length);
            Position(pos + length);
        }

        public ByteOrder Order()
        {
            return ByteOrder.LITTLE_ENDIAN;
        }

        public void Put(ByteBuffer src)
        {
            int pos = Position();
            int sbpos = src.Position();
            int n = src.Limit() - sbpos;
            if (n > Limit() - pos)
                throw new BufferOverflowException();
            System.Buffer.BlockCopy(src.mRaw, src.Index(sbpos),
                mRaw, Index(pos), n);
            src.Position(sbpos + n);
            Position(pos + n);
        }


        public void Put(byte[] src, int offset, int length)
        {
            var pos = mPosition;
            if (length > mLimit - pos)
            {
                throw new BufferOverflowException();
            }

            if (offset > src.Length || offset + length > src.Length || offset < 0)
            {
                throw new System.IndexOutOfRangeException();
            }

            System.Buffer.BlockCopy(src, offset, mRaw, Index(pos), length);
            Position(pos + length);
        }

        private void Put(int dstOffset, byte[] src, int offset, int length)
        {
            var pos = dstOffset;
            if (length > mLimit - pos)
            {
                throw new BufferOverflowException();
            }

            System.Buffer.BlockCopy(src, offset, mRaw, Index(pos), length);
        }

        public void PutShort(int offset, short value)
        {
            Put(offset, BitConverter.GetBytes(value), 0, 2);
        }


        public void PutLong(long value)
        {
            Put(BitConverter.GetBytes(value));
        }

        public void PutInt(int offset, int value)
        {
            Put(offset, BitConverter.GetBytes(value), 0, 4);
        }

        public void PutShort(short value)
        {
            Put(BitConverter.GetBytes(value));
        }

        public ByteBuffer PutInt(int value)
        {
            Put(BitConverter.GetBytes(value));
            return this;
        }

        public ByteBuffer Duplicate()
        {
            return new ByteBuffer(
                mRaw,
                mMark,
                mPosition,
                mLimit,
                mCapacity,
                mOffset);
        }


        public void Put(byte x)
        {
            mRaw[Index(NextPutIndex())] = x;
        }


        public ByteBuffer AsReadOnlyBuffer()
        {
            return this;
        }

        public static ByteBuffer Allocate(int capacity)
        {
            return new ByteBuffer(capacity, capacity);
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

        public void Put(byte[] src)
        {
            Put(src, 0, src.Length);
        }

        public static ByteBuffer Wrap(byte[] src)
        {
            return new ByteBuffer(src, 0, src.Length);
        }

        public static ByteBuffer Wrap(byte[] src, int offset, int length)
        {
            return new ByteBuffer(src, offset, length);
        }

        public static ByteBuffer AllocateDirect(int size)
        {
            return Allocate(size);
        }

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