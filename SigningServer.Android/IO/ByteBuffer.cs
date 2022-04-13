using System;

namespace SigningServer.Android.IO
{
    public enum ByteOrder
    {
        LITTLE_ENDIAN = 0,
    }

    public abstract class Buffer
    {
        protected int _capacity;

        protected int _mark = -1;
        protected int _position;
        protected int _limit;

        public int Capacity()
        {
            return _capacity;
        }

        public int Limit()
        {
            return _limit;
        }


        protected Buffer(int mark, int pos, int lim, int cap)
        {
            // package-private
            if (cap < 0)
            {
                throw CreateCapacityException(cap);
            }

            this._capacity = cap;
            Limit(lim);
            Position(pos);
            if (mark >= 0)
            {
                if (mark > pos)
                    throw new ArgumentException("mark > position: ("
                                                + mark + " > " + pos + ")");
                this._mark = mark;
            }
        }

        public Buffer Limit(int newLimit)
        {
            if (newLimit > _capacity | newLimit < 0)
                throw CreateLimitException(newLimit);
            _limit = newLimit;
            if (_position > newLimit) _position = newLimit;
            if (_mark > newLimit) _mark = -1;
            return this;
        }

        public int Position()
        {
            return _position;
        }

        public Buffer Position(int newPosition)
        {
            if (newPosition > _limit | newPosition < 0)
                throw CreatePositionException(newPosition);
            if (_mark > newPosition) _mark = -1;
            _position = newPosition;
            return this;
        }

        private ArgumentException CreatePositionException(int newPosition)
        {
            String msg = null;

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
            String msg = null;

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

        static ArgumentException CreateCapacityException(int capacity)
        {
            return new ArgumentException("capacity < 0: ("
                                         + capacity + " < 0)");
        }


        public int Remaining()
        {
            var rem = _limit - _position;
            return rem > 0 ? rem : 0;
        }


        public virtual int NextGetIndex()
        {
            var p = _position;
            if (p >= _limit)
            {
                throw new BufferUnderflowException();
            }

            _position = p + 1;
            return p;
        }

        protected virtual int CheckIndex(int i)
        {
            if (i < 0 || i >= _limit)
            {
                throw new IndexOutOfRangeException();
            }

            return i;
        }

        protected virtual int nextGetIndex(int nb)
        {
            var p = _position;
            if (_limit - p < nb)
            {
                throw new BufferUnderflowException();
            }

            _position = p + nb;
            return p;
        }

        protected virtual int CheckIndex(int i, int nb)
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
            int p = _position;
            if (p >= _limit)
            {
                throw new BufferOverflowException();
            }

            _position = p + 1;
            return p;
        }
    }

    public abstract class ByteBuffer : Buffer
    {
        protected internal sbyte[] _raw;
        protected int _offset;

        public ByteBuffer Order(ByteOrder byteOrder)
        {
            return this;
        }

        public abstract ByteBuffer Slice();
        public abstract sbyte Get();
        public abstract sbyte Get(int i);

        protected ByteBuffer(int mark, int pos, int lim, int cap, // package-private
            sbyte[] hb, int offset)
            : base(mark, pos, lim, cap)
        {
            this._raw = hb;
            this._offset = offset;
        }

        public abstract long GetLong();
        public abstract short GetShort();
        public abstract int GetInt();
        public abstract long GetLong(int offset);
        public abstract void Get(sbyte[] dst);
        public abstract int GetInt(int i);
        public abstract short GetShort(int i);
        public abstract void Get(sbyte[] dst, int offset, int length);

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
            return _raw != null;
        }

        public sbyte[] Array()
        {
            return _raw;
        }

        public int ArrayOffset()
        {
            return _offset;
        }

        public abstract ByteOrder Order();
        public abstract void Put(ByteBuffer src);


        public void Put(sbyte[] src)
        {
            Put(src, 0, src.Length);
        }

        public abstract void Put(sbyte[] src, int offset, int length);
        public abstract void PutShort(int offset, short value);
        public abstract void PutLong(long value);
        public abstract void PutInt(int offset, int value);
        public abstract void PutShort(short value);
        public abstract ByteBuffer PutInt(int value);


        public static ByteBuffer Wrap(sbyte[] src)
        {
            return new HeapByteBuffer(src, 0, src.Length);
        }

        public static ByteBuffer Wrap(sbyte[] src, int offset, int length)
        {
            return new HeapByteBuffer(src, offset, length);
        }

        public static ByteBuffer AllocateDirect(int size)
        {
            return Allocate(size);
        }

        public abstract ByteBuffer Duplicate();
        public abstract void Put(sbyte x);

        public int CompareTo(ByteBuffer that)
        {
            int thisPos = this.Position();
            int thisRem = this.Limit() - thisPos;
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
                return this.Get(thisPos + i).CompareTo(that.Get(thatPos + i));
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

    public class HeapByteBuffer : ByteBuffer
    {
        protected HeapByteBuffer(sbyte[] buf,
            int mark, int pos, int lim, int cap,
            int off)
            : base(mark, pos, lim, cap, buf, off)
        {
        }

        internal HeapByteBuffer(int cap, int lim) : base(-1, 0, lim, cap, new sbyte[cap], 0)
        {
        }

        internal HeapByteBuffer(sbyte[] buf, int off, int len)
            : base(-1, off, off + len, buf.Length, buf, 0)
        {
        }

        public override ByteBuffer Slice()
        {
            int pos = this.Position();
            int lim = this.Limit();
            int rem = (pos <= lim ? lim - pos : 0);
            return new HeapByteBuffer(_raw,
                -1,
                0,
                rem,
                rem,
                pos + _offset);
        }

        public override sbyte Get()
        {
            return _raw[Index(NextGetIndex())];
        }

        public override sbyte Get(int i)
        {
            return _raw[Index(CheckIndex(i))];
        }

        private int Index(int i)
        {
            return i + _offset;
        }

        public override long GetLong()
        {
            return BitConverter.ToInt64(_raw, Index(nextGetIndex(8)));
        }

        public override short GetShort()
        {
            return BitConverter.ToInt16(_raw, Index(nextGetIndex(2)));
        }

        public override int GetInt()
        {
            return BitConverter.ToInt32(_raw, Index(nextGetIndex(4)));
        }

        public override long GetLong(int offset)
        {
            return BitConverter.ToInt64(_raw, Index(CheckIndex(offset, 8)));
        }

        public override void Get(sbyte[] dst)
        {
            Get(dst, 0, dst.Length);
        }

        public override int GetInt(int i)
        {
            return BitConverter.ToInt32(_raw, Index(CheckIndex(i, 4)));
        }

        public override short GetShort(int i)
        {
            return BitConverter.ToInt16(_raw, Index(CheckIndex(i, 2)));
        }


        public override void Get(sbyte[] dst, int offset, int length)
        {
            int pos = Position();
            if (length > Limit() - pos)
            {
                throw new BufferUnderflowException();
            }

            System.Array.Copy(_raw, Index(pos), dst, offset, length);
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
                System.Array.Copy(sb._raw, sb.Index(sbpos),
                    _raw, Index(pos), n);
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


        public override void Put(sbyte[] src, int offset, int length)
        {
            var pos = _position;
            if (length > _limit - pos)
            {
                throw new BufferOverflowException();
            }

            if (offset > src.Length || offset + length > src.Length)
            {
                throw new ArgumentOutOfRangeException();
            }

            System.Array.Copy(src, offset, _raw, Index(pos), length);
            Position(pos + length);
        }

        protected void put(int dstOffset, byte[] src, int offset, int length)
        {
            var pos = dstOffset;
            if (length > _limit - pos)
            {
                throw new BufferOverflowException();
            }

            System.Array.Copy(src, offset, _raw, Index(pos), length);
        }

        public override void PutShort(int offset, short value)
        {
            put(offset, BitConverter.GetBytes(value), 0, 2);
        }


        public override void PutLong(long value)
        {
            Put(BitConverter.GetBytes(value));
        }

        public override void PutInt(int offset, int value)
        {
            put(offset, BitConverter.GetBytes(value), 0, 4);
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
                _raw,
                _mark,
                _position,
                _limit,
                _capacity,
                _offset);
        }


        public override void Put(sbyte x)
        {
            _raw[Index(NextPutIndex())] = x;
        }
    }
}