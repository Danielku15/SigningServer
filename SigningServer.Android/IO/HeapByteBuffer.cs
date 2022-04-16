using System;

namespace SigningServer.Android.IO
{
    public class HeapByteBuffer : ByteBuffer
    {
        private HeapByteBuffer(byte[] buf,
            int mark, int pos, int lim, int cap,
            int off)
            : base(mark, pos, lim, cap, buf, off)
        {
        }

        internal HeapByteBuffer(int cap, int lim) : base(-1, 0, lim, cap, new byte[cap], 0)
        {
        }

        internal HeapByteBuffer(byte[] buf, int off, int len)
            : base(-1, off, off + len, buf.Length, buf, 0)
        {
        }

        public override ByteBuffer Slice()
        {
            int pos = Position();
            int lim = Limit();
            int rem = (pos <= lim ? lim - pos : 0);
            return new HeapByteBuffer(mRaw,
                -1,
                0,
                rem,
                rem,
                pos + mOffset);
        }

        public override byte Get()
        {
            return mRaw[Index(NextGetIndex())];
        }

        public override byte Get(int i)
        {
            return mRaw[Index(CheckIndex(i))];
        }

        private int Index(int i)
        {
            return i + mOffset;
        }

        public override long GetLong()
        {
            return BitConverter.ToInt64(mRaw, Index(NextGetIndex(8)));
        }

        public override short GetShort()
        {
            return BitConverter.ToInt16(mRaw, Index(NextGetIndex(2)));
        }

        public override int GetInt()
        {
            return BitConverter.ToInt32(mRaw, Index(NextGetIndex(4)));
        }

        public override long GetLong(int offset)
        {
            return BitConverter.ToInt64(mRaw, Index(CheckIndex(offset, 8)));
        }

        public override void Get(byte[] dst)
        {
            Get(dst, 0, dst.Length);
        }

        public override int GetInt(int i)
        {
            return BitConverter.ToInt32(mRaw, Index(CheckIndex(i, 4)));
        }

        public override short GetShort(int i)
        {
            return BitConverter.ToInt16(mRaw, Index(CheckIndex(i, 2)));
        }


        public override void Get(byte[] dst, int offset, int length)
        {
            int pos = Position();
            if (length > Limit() - pos)
            {
                throw new BufferUnderflowException();
            }

            System.Buffer.BlockCopy(mRaw, Index(pos), dst, offset, length);
            Position(pos + length);
        }

        public override ByteOrder Order()
        {
            return ByteOrder.LITTLE_ENDIAN;
        }

        public override void Put(ByteBuffer src)
        {
            if (src is HeapByteBuffer sb)
            {
                int pos = Position();
                int sbpos = sb.Position();
                int n = sb.Limit() - sbpos;
                if (n > Limit() - pos)
                    throw new BufferOverflowException();
                System.Buffer.BlockCopy(sb.mRaw, sb.Index(sbpos),
                    mRaw, Index(pos), n);
                sb.Position(sbpos + n);
                Position(pos + n);
            }
            else
            {
                int n = src.Remaining();
                for (int i = 0; i < n; i++)
                {
                    Put(src.Get());
                }
            }
        }


        public override void Put(byte[] src, int offset, int length)
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

        public override void PutShort(int offset, short value)
        {
            Put(offset, BitConverter.GetBytes(value), 0, 2);
        }


        public override void PutLong(long value)
        {
            Put(BitConverter.GetBytes(value));
        }

        public override void PutInt(int offset, int value)
        {
            Put(offset, BitConverter.GetBytes(value), 0, 4);
        }

        public override void PutShort(short value)
        {
            Put(BitConverter.GetBytes(value));
        }

        public override ByteBuffer PutInt(int value)
        {
            Put(BitConverter.GetBytes(value));
            return this;
        }

        public override ByteBuffer Duplicate()
        {
            return new HeapByteBuffer(
                mRaw,
                mMark,
                mPosition,
                mLimit,
                mCapacity,
                mOffset);
        }


        public override void Put(byte x)
        {
            mRaw[Index(NextPutIndex())] = x;
        }
    }
}