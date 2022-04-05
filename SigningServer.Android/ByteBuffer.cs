using System;

namespace SigningServer.Android
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

        public int capacity()
        {
            return _capacity;
        }

        public int limit()
        {
            return _limit;
        }


        protected Buffer(int mark, int pos, int lim, int cap)
        {
            // package-private
            if (cap < 0)
            {
                throw createCapacityException(cap);
            }

            this._capacity = cap;
            limit(lim);
            position(pos);
            if (mark >= 0)
            {
                if (mark > pos)
                    throw new ArgumentException("mark > position: ("
                                                + mark + " > " + pos + ")");
                this._mark = mark;
            }
        }

        public Buffer limit(int newLimit)
        {
            if (newLimit > _capacity | newLimit < 0)
                throw createLimitException(newLimit);
            _limit = newLimit;
            if (_position > newLimit) _position = newLimit;
            if (_mark > newLimit) _mark = -1;
            return this;
        }

        public int position()
        {
            return _position;
        }

        public Buffer position(int newPosition)
        {
            if (newPosition > _limit | newPosition < 0)
                throw createPositionException(newPosition);
            if (_mark > newPosition) _mark = -1;
            _position = newPosition;
            return this;
        }

        private ArgumentException createPositionException(int newPosition)
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

        private ArgumentException createLimitException(int newLimit)
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

        static ArgumentException createCapacityException(int capacity)
        {
            return new ArgumentException("capacity < 0: ("
                                         + capacity + " < 0)");
        }


        public int remaining()
        {
            var rem = _limit - _position;
            return rem > 0 ? rem : 0;
        }


        protected virtual int nextGetIndex()
        {
            var p = _position;
            if (p >= _limit)
            {
                throw new BufferUnderflowException();
            }

            _position = p + 1;
            return p;
        }

        protected virtual int checkIndex(int i)
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

        protected virtual int checkIndex(int i, int nb)
        {
            if (i < 0 || (nb > _limit - i))
            {
                throw new IndexOutOfRangeException();
            }

            return i;
        }

        public void flip()
        {
            _limit = _position;
            _position = 0;
            _mark = 0;
        }

        public bool hasRemaining()
        {
            return _position < _limit;
        }

        public void rewind()
        {
            _position = 0;
            _mark = -1;
        }

        public void clear()
        {
            _position = 0;
            _limit = _capacity;
            _mark = -1;
        }
        
        public void mark()
        {
            _mark = _position;
        }

        public void reset()
        {
            var m = _mark;
            if (m < 0)
            {
                throw new InvalidOperationException();
            }

            _position = m;
        }

        protected int nextPutIndex()
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
        protected internal byte[] _raw;
        protected int _offset;

        public ByteBuffer order(ByteOrder byteOrder)
        {
            return this;
        }

        public abstract ByteBuffer slice();
        public abstract byte get();
        public abstract byte get(int i);

        protected ByteBuffer(int mark, int pos, int lim, int cap, // package-private
            byte[] hb, int offset)
            : base(mark, pos, lim, cap)
        {
            this._raw = hb;
            this._offset = offset;
        }

        public abstract long getLong();
        public abstract short getShort();
        public abstract int getInt();
        public abstract long getLong(int offset);
        public abstract void get(byte[] dst);
        public abstract int getInt(int i);
        public abstract short getShort(int i);
        public abstract void get(byte[] dst, int offset, int length);

        public ByteBuffer asReadOnlyBuffer()
        {
            return this;
        }

        public static ByteBuffer allocate(int capacity)
        {
            return new HeapByteBuffer(capacity, capacity);
        }


        public bool hasArray()
        {
            return _raw != null;
        }

        public byte[] array()
        {
            return _raw;
        }

        public int arrayOffset()
        {
            return _offset;
        }

        public abstract ByteOrder order();
        public abstract void put(ByteBuffer src);


        public void put(byte[] src)
        {
            put(src, 0, src.Length);
        }

        public abstract void put(byte[] src, int offset, int length);
        public abstract void putShort(int offset, short value);
        public abstract void putLong(long value);
        public abstract void putInt(int offset, int value);
        public abstract void putShort(short value);
        public abstract ByteBuffer putInt(int value);


        public static ByteBuffer wrap(byte[] src)
        {
            return new HeapByteBuffer(src, 0, src.Length);
        }

        public static ByteBuffer wrap(byte[] src, int offset, int length)
        {
            return new HeapByteBuffer(src, offset, length);
        }

        public static ByteBuffer allocateDirect(int size)
        {
            return allocate(size);
        }

        public abstract ByteBuffer duplicate();
        public abstract void put(byte x);

        public int compareTo(ByteBuffer that)
        {
            int thisPos = this.position();
            int thisRem = this.limit() - thisPos;
            int thatPos = that.position();
            int thatRem = that.limit() - thatPos;
            int length = Math.Min(thisRem, thatRem);
            if (length < 0)
                return -1;
            int i = mismatch(this, thisPos,
                that, thatPos,
                length);
            if (i >= 0)
            {
                return this.get(thisPos + i).CompareTo(that.get(thatPos + i));
            }

            return thisRem - thatRem;
        }
        
        
        private int mismatch(ByteBuffer a, int aOff, ByteBuffer b, int bOff, int length)
        {
            for (int i = 0; i < length; i++)
            {
                if (a.get(aOff + i) != b.get(bOff + i))
                {
                    return i;
                }
            }

            return -1;
        }
    }

    public class HeapByteBuffer : ByteBuffer
    {
        protected HeapByteBuffer(byte[] buf,
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

        public override ByteBuffer slice()
        {
            int pos = this.position();
            int lim = this.limit();
            int rem = (pos <= lim ? lim - pos : 0);
            return new HeapByteBuffer(_raw,
                -1,
                0,
                rem,
                rem,
                pos + _offset);
        }

        public override byte get()
        {
            return _raw[index(nextGetIndex())];
        }

        public override byte get(int i)
        {
            return _raw[index(checkIndex(i))];
        }

        private int index(int i)
        {
            return i + _offset;
        }

        public override long getLong()
        {
            return BitConverter.ToInt64(_raw, index(nextGetIndex(8)));
        }

        public override short getShort()
        {
            return BitConverter.ToInt16(_raw, index(nextGetIndex(2)));
        }

        public override int getInt()
        {
            return BitConverter.ToInt32(_raw, index(nextGetIndex(4)));
        }

        public override long getLong(int offset)
        {
            return BitConverter.ToInt64(_raw, index(checkIndex(offset, 8)));
        }

        public override void get(byte[] dst)
        {
            get(dst, 0, dst.Length);
        }

        public override int getInt(int i)
        {
            return BitConverter.ToInt32(_raw, index(checkIndex(i, 4)));
        }

        public override short getShort(int i)
        {
            return BitConverter.ToInt16(_raw, index(checkIndex(i, 2)));
        }


        public override void get(byte[] dst, int offset, int length)
        {
            int pos = position();
            if (length > limit() - pos)
            {
                throw new BufferUnderflowException();
            }

            Array.Copy(_raw, index(pos), dst, offset, length);
            position(pos + length);
        }

        public override ByteOrder order()
        {
            return ByteOrder.LITTLE_ENDIAN;
        }


        public override void put(ByteBuffer src)
        {
            if (src is HeapByteBuffer sb)
            {
                int pos = position();
                int sbpos = sb.position();
                int n = sb.limit() - sbpos;
                if (n > limit() - pos)
                    throw new BufferOverflowException();
                Array.Copy(sb._raw, sb.index(sbpos),
                    _raw, index(pos), n);
                sb.position(sbpos + n);
                position(pos + n);
            }
            else
            {
                int n = src.remaining();
                for (int i = 0; i < n; i++)
                {
                    put(src.get());
                }
            }
        }


        public override void put(byte[] src, int offset, int length)
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

            Array.Copy(src, offset, _raw, index(pos), length);
            position(pos + length);
        }

        protected void put(int dstOffset, byte[] src, int offset, int length)
        {
            var pos = dstOffset;
            if (length > _limit - pos)
            {
                throw new BufferOverflowException();
            }

            Array.Copy(src, offset, _raw, index(pos), length);
        }

        public override void putShort(int offset, short value)
        {
            put(offset, BitConverter.GetBytes(value), 0, 2);
        }


        public override void putLong(long value)
        {
            put(BitConverter.GetBytes(value));
        }

        public override void putInt(int offset, int value)
        {
            put(offset, BitConverter.GetBytes(value), 0, 4);
        }

        public override void putShort(short value)
        {
            put(BitConverter.GetBytes(value));
        }

        public override ByteBuffer putInt(int value)
        {
            put(BitConverter.GetBytes(value));
            return this;
        }

        public override ByteBuffer duplicate()
        {
            return new HeapByteBuffer(
                _raw,
                _mark,
                _position,
                _limit,
                _capacity,
                _offset);
        }


        public override void put(byte x)
        {
            _raw[index(nextPutIndex())] = x;
        }
    }
}