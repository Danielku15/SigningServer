using System;
using System.Runtime.InteropServices;

namespace SigningServer.Android
{
    public enum ByteOrder
    {
        LITTLE_ENDIAN = 0,
    }

    public class ByteBuffer
    {
        private byte[] _raw;
        private int _offset;
        private int _mark = -1;
        private int _position;
        private int _limit;
        private int _capacity;

        public ByteBuffer(byte[] buf, int off, int len)
        {
            _raw = buf;
            _offset = off;
            _limit = off + len;
            _capacity = off + len;
        }

        public ByteBuffer order(ByteOrder byteOrder)
        {
            return this;
        }

        public int capacity()
        {
            return _capacity;
        }

        public ByteBuffer slice()
        {
            int pos = this.position();
            int lim = this.limit();
            int rem = (pos <= lim ? lim - pos : 0);
            return new ByteBuffer(_raw,
                pos,
                rem);
        }

        public int remaining()
        {
            var rem = _limit - _position;
            return rem > 0 ? rem : 0;
        }

        public int position()
        {
            return _position;
        }

        public void position(int newPosition)
        {
            if (newPosition > _limit | newPosition < 0)
            {
                throw new ArgumentOutOfRangeException();
            }

            if (_mark > newPosition) _mark = -1;
            _position = newPosition;
        }

        public int limit()
        {
            return _limit;
        }

        public void limit(int newLimit)
        {
            if (newLimit > _capacity | newLimit < 0)
            {
                throw new ArgumentOutOfRangeException();
            }

            _limit = newLimit;
            if (_position > newLimit) _position = newLimit;
            if (_mark > newLimit) _mark = -1;
        }

        public byte get()
        {
            return _raw[index(nextGetIndex())];
        }

        private int nextGetIndex()
        {
            var p = _position;
            if (p >= _limit)
            {
                throw new BufferUnderflowException();
            }

            _position = p + 1;
            return p;
        }

        private int index(int i)
        {
            return i + _offset;
        }

        public byte get(int i)
        {
            return _raw[index(checkIndex(i))];
        }

        private int checkIndex(int i)
        {
            if (i < 0 || i >= _limit)
            {
                throw new IndexOutOfRangeException();
            }

            return i;
        }

        public long getLong()
        {
            return BitConverter.ToInt64(_raw, nextGetIndex(8));
        }

        private int nextGetIndex(int nb)
        {
            var p = _position;
            if (_limit - p < nb)
            {
                throw new BufferUnderflowException();
            }

            _position = p + nb;
            return p;
        }

        public short getShort()
        {
            return BitConverter.ToInt16(_raw, nextGetIndex(2));
        }

        public int getInt()
        {
            return BitConverter.ToInt16(_raw, nextGetIndex(4));
        }

        public long getLong(int offset)
        {
            return BitConverter.ToInt64(_raw, checkIndex(offset, 8));
        }

        private int checkIndex(int i, int nb)
        {
            if (i < 0 || (nb > _limit - i))
            {
                throw new IndexOutOfRangeException();
            }

            return i;
        }

        public void get(byte[] dst)
        {
            get(dst, 0, dst.Length);
        }

        public int getInt(int i)
        {
            return BitConverter.ToInt32(_raw, checkIndex(i, 4));
        }

        public short getShort(int i)
        {
            return BitConverter.ToInt16(_raw, checkIndex(i, 2));
        }


        public void get(byte[] dst, int offset, int length)
        {
            int pos = position();
            if (length > limit() - pos)
            {
                throw new BufferUnderflowException();
            }

            Array.Copy(_raw, index(pos), dst, offset, length);
            position(pos + length);
        }


        public static ByteBuffer allocate(int i)
        {
            return new ByteBuffer(new byte[i], 0, i);
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


        public ByteOrder order()
        {
            return ByteOrder.LITTLE_ENDIAN;
        }


        public void put(ByteBuffer src)
        {
            var rem = src.remaining();
            var pos = src.position();
            put(src._raw, pos, rem);
            src.position(pos + rem);
        }

        public void put(byte[] src)
        {
            put(src, 0, src.Length);
        }


        public void put(byte[] src, int offset, int length)
        {
            var pos = _position;
            if (length > _limit - pos)
            {
                throw new BufferOverflowException();
            }

            Array.Copy(src, offset, _raw, index(pos), length);
            position(pos + length);
        }

        public void put(int dstOffset, byte[] src, int offset, int length)
        {
            var pos = dstOffset;
            if (length > _limit - pos)
            {
                throw new BufferOverflowException();
            }

            Array.Copy(src, offset, _raw, index(pos), length);
            position(pos + length);
        }

        public void putShort(int offset, short value)
        {
            put(offset, BitConverter.GetBytes(value), 0, 2);
        }


        public void putLong(long value)
        {
            put(BitConverter.GetBytes(value));
        }

        public void putInt(int offset, int value)
        {
            put(offset, BitConverter.GetBytes(value), 0, 4);
        }

        public void putShort(short value)
        {
            put(BitConverter.GetBytes(value));
        }

        public ByteBuffer putInt(int value)
        {
            put(BitConverter.GetBytes(value));
            return this;
        }

        public static ByteBuffer wrap(byte[] src)
        {
            return new ByteBuffer(src, 0, src.Length);
        }

        public static ByteBuffer wrap(byte[] src, int offset, int length)
        {
            return new ByteBuffer(src, offset, length);
        }


        public void rewind()
        {
            _position = 0;
            _mark = -1;
        }

        public static ByteBuffer allocateDirect(int size)
        {
            return allocate(size);
        }

        public void clear()
        {
            _position = 0;
            _limit = _capacity;
            _mark = -1;
        }

        public ByteBuffer asReadOnlyBuffer()
        {
            return this;
        }

        public ByteBuffer duplicate()
        {
            var b = new ByteBuffer(_raw, _offset, _limit)
            {
                _capacity = _capacity,
                _limit = _limit,
                _mark = _mark,
                _offset = _offset,
                _position = _position,
                _raw = _raw
            };
            return b;
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


        public void put(byte x)
        {
            _raw[index(nextPutIndex())] = x;
        }

        private int nextPutIndex()
        {
            int p = _position;
            if (p >= _limit)
            {
                throw new BufferOverflowException();
            }

            _position = p + 1;
            return p;
        }

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
}