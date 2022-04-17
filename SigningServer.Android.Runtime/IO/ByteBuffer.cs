using System;

namespace SigningServer.Android.IO
{
    public class ByteBuffer
    {
        private readonly byte[] _raw;
        private readonly int _offset;
        private readonly int _capacity;
        private int _mark = -1;
        private int _position;
        private int _limit;

        public int Capacity()
        {
            return _capacity;
        }

        public int Limit()
        {
            return _limit;
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
            _raw = hb;
            _offset = offset;
        }

        protected ByteBuffer(int mark, int pos, int lim, int cap)
        {
            if (cap < 0)
            {
                throw CreateCapacityException(cap);
            }

            _capacity = cap;
            Limit(lim);
            Position(pos);
            if (mark >= 0)
            {
                if (mark > pos)
                    throw new ArgumentException("mark > position: ("
                                                + mark + " > " + pos + ")");
                _mark = mark;
            }
        }

        public void Limit(int newLimit)
        {
            if (newLimit > _capacity | newLimit < 0)
                throw CreateLimitException(newLimit);
            _limit = newLimit;
            if (_position > newLimit) _position = newLimit;
            if (_mark > newLimit) _mark = -1;
        }

        public int Position()
        {
            return _position;
        }

        public void Position(int newPosition)
        {
            if (newPosition > _limit | newPosition < 0)
                throw CreatePositionException(newPosition);
            if (_mark > newPosition) _mark = -1;
            _position = newPosition;
        }

        private ArgumentException CreatePositionException(int newPosition)
        {
            string msg;

            if (newPosition > _limit)
            {
                msg = "newPosition > limit: (" + newPosition + " > " + _limit + ")";
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
            string msg = null;

            if (newLimit > _capacity)
            {
                msg = "newLimit > capacity: (" + newLimit + " > " + _capacity + ")";
            }
            else
            {
                // assume negative
                msg = "newLimit < 0: (" + newLimit + " < 0)";
            }

            return new ArgumentException(msg);
        }

        private static ArgumentException CreateCapacityException(int capacity)
        {
            return new ArgumentException("capacity < 0: ("
                                         + capacity + " < 0)");
        }


        public int Remaining()
        {
            var rem = _limit - _position;
            return rem > 0 ? rem : 0;
        }


        public int NextGetIndex()
        {
            var p = _position;
            if (p >= _limit)
            {
                throw new BufferUnderflowException();
            }

            _position = p + 1;
            return p;
        }

        protected int CheckIndex(int i)
        {
            if (i < 0 || i >= _limit)
            {
                throw new IndexOutOfRangeException();
            }

            return i;
        }

        protected int NextGetIndex(int nb)
        {
            var p = _position;
            if (_limit - p < nb)
            {
                throw new BufferUnderflowException();
            }

            _position = p + nb;
            return p;
        }

        // ReSharper disable once ParameterOnlyUsedForPreconditionCheck.Global
        protected int CheckIndex(int i, int nb)
        {
            if (i < 0 || (nb > _limit - i))
            {
                throw new IndexOutOfRangeException();
            }

            return i;
        }

        public void Flip()
        {
            _limit = _position;
            _position = 0;
            _mark = 0;
        }

        public bool HasRemaining()
        {
            return _position < _limit;
        }

        public void Rewind()
        {
            _position = 0;
            _mark = -1;
        }

        public void Clear()
        {
            _position = 0;
            _limit = _capacity;
            _mark = -1;
        }

        public void Mark()
        {
            _mark = _position;
        }

        public void Reset()
        {
            var m = _mark;
            if (m < 0)
            {
                throw new InvalidOperationException();
            }

            _position = m;
        }

        protected int NextPutIndex()
        {
            var p = _position;
            if (p >= _limit)
            {
                throw new BufferOverflowException();
            }

            _position = p + 1;
            return p;
        }

        // ReSharper disable once UnusedParameter.Global
        public ByteBuffer Order(ByteOrder byteOrder)
        {
            return this;
        }

        public ByteBuffer Slice()
        {
            var pos = Position();
            var lim = Limit();
            var rem = (pos <= lim ? lim - pos : 0);
            return new ByteBuffer(_raw,
                -1,
                0,
                rem,
                rem,
                pos + _offset);
        }

        public byte Get()
        {
            return _raw[Index(NextGetIndex())];
        }

        public byte Get(int i)
        {
            return _raw[Index(CheckIndex(i))];
        }

        private int Index(int i)
        {
            return i + _offset;
        }

        public long GetLong()
        {
            return BitConverter.ToInt64(_raw, Index(NextGetIndex(8)));
        }

        public short GetShort()
        {
            return BitConverter.ToInt16(_raw, Index(NextGetIndex(2)));
        }

        public int GetInt()
        {
            return BitConverter.ToInt32(_raw, Index(NextGetIndex(4)));
        }

        public long GetLong(int offset)
        {
            return BitConverter.ToInt64(_raw, Index(CheckIndex(offset, 8)));
        }

        public void Get(byte[] dst)
        {
            Get(dst, 0, dst.Length);
        }

        public int GetInt(int i)
        {
            return BitConverter.ToInt32(_raw, Index(CheckIndex(i, 4)));
        }

        public short GetShort(int i)
        {
            return BitConverter.ToInt16(_raw, Index(CheckIndex(i, 2)));
        }


        public void Get(byte[] dst, int offset, int length)
        {
            var pos = Position();
            if (length > Limit() - pos)
            {
                throw new BufferUnderflowException();
            }

            Buffer.BlockCopy(_raw, Index(pos), dst, offset, length);
            Position(pos + length);
        }

        public ByteOrder Order()
        {
            return ByteOrder.LITTLE_ENDIAN;
        }

        public void Put(ByteBuffer src)
        {
            var pos = Position();
            var sbpos = src.Position();
            var n = src.Limit() - sbpos;
            if (n > Limit() - pos)
                throw new BufferOverflowException();
            Buffer.BlockCopy(src._raw, src.Index(sbpos),
                _raw, Index(pos), n);
            src.Position(sbpos + n);
            Position(pos + n);
        }


        public void Put(byte[] src, int offset, int length)
        {
            var pos = _position;
            if (length > _limit - pos)
            {
                throw new BufferOverflowException();
            }

            if (offset > src.Length || offset + length > src.Length || offset < 0)
            {
                throw new IndexOutOfRangeException();
            }

            Buffer.BlockCopy(src, offset, _raw, Index(pos), length);
            Position(pos + length);
        }

        private void Put(int dstOffset, byte[] src, int offset, int length)
        {
            var pos = dstOffset;
            if (length > _limit - pos)
            {
                throw new BufferOverflowException();
            }

            Buffer.BlockCopy(src, offset, _raw, Index(pos), length);
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
                _raw,
                _mark,
                _position,
                _limit,
                _capacity,
                _offset);
        }


        public void Put(byte x)
        {
            _raw[Index(NextPutIndex())] = x;
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
            return _raw != null;
        }

        public byte[] Array()
        {
            return _raw;
        }

        public int ArrayOffset()
        {
            return _offset;
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
            var thisPos = Position();
            var thisRem = Limit() - thisPos;
            var thatPos = that.Position();
            var thatRem = that.Limit() - thatPos;
            var length = System.Math.Min(thisRem, thatRem);
            if (length < 0)
                return -1;
            var i = Mismatch(this, thisPos,
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
            for (var i = 0; i < length; i++)
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
