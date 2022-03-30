namespace SigningServer.Android
{
    public enum ByteOrder
    {
        LITTLE_ENDIAN = 0,
        BIG_ENDIAN = 1
    }

    public class ByteBuffer
    {
        public ByteBuffer order(ByteOrder byteOrder)
        {
            throw new System.NotImplementedException();
        }

        public long getLong(int offset)
        {
            throw new System.NotImplementedException();
        }

        public int capacity()
        {
            throw new System.NotImplementedException();
        }

        public ByteBuffer slice()
        {
            throw new System.NotImplementedException();
        }

        public int remaining()
        {
            throw new System.NotImplementedException();
        }

        public int position()
        {
            throw new System.NotImplementedException();
        }

        public int getInt()
        {
            throw new System.NotImplementedException();
        }

        public void position(int i)
        {
            throw new System.NotImplementedException();
        }

        public short getShort()
        {
            throw new System.NotImplementedException();
        }

        public int limit()
        {
            throw new System.NotImplementedException();
        }

        public void limit(int recordEndInBuf)
        {
            throw new System.NotImplementedException();
        }

        public void put(ByteBuffer byteBuffer)
        {
            throw new System.NotImplementedException();
        }

        public static ByteBuffer allocate(int i)
        {
            throw new System.NotImplementedException();
        }

        public void flip()
        {
            throw new System.NotImplementedException();
        }

        public void put(byte[] byteBuffer)
        {
            throw new System.NotImplementedException();
        }

        public bool hasRemaining()
        {
            throw new System.NotImplementedException();
        }

        public bool hasArray()
        {
            throw new System.NotImplementedException();
        }

        public byte[] array()
        {
            throw new System.NotImplementedException();
        }

        public int arrayOffset()
        {
            throw new System.NotImplementedException();
        }

        public void get(byte[] nameBytes)
        {
            throw new System.NotImplementedException();
        }

        public int getInt(int eocdStartPos)
        {
            throw new System.NotImplementedException();
        }

        public ByteOrder order()
        {
            throw new System.NotImplementedException();
        }

        public short getShort(int offset)
        {
            throw new System.NotImplementedException();
        }

        public void putShort(int offset, short value)
        {
            throw new System.NotImplementedException();
        }

        public void putInt(int offset, int value)
        {
            throw new System.NotImplementedException();
        }

        public void putShort(short value)
        {
            throw new System.NotImplementedException();
        }

        public void putInt(int value)
        {
            throw new System.NotImplementedException();
        }

        public static ByteBuffer wrap(byte[] result)
        {
            throw new System.NotImplementedException();
        }

        public void get(byte[] mInputBuffer, int i, int chunkSize)
        {
            throw new System.NotImplementedException();
        }

        public static ByteBuffer wrap(byte[] mSinkMArray, int mSliceOffset, int size)
        {
            throw new System.NotImplementedException();
        }

        public void put(byte[] mSinkMArray, int mSliceOffset, int size)
        {
            throw new System.NotImplementedException();
        }

        public void rewind()
        {
            throw new System.NotImplementedException();
        }

        public static ByteBuffer allocateDirect(int min)
        {
            throw new System.NotImplementedException();
        }

        public void clear()
        {
            throw new System.NotImplementedException();
        }

        public ByteBuffer asReadOnlyBuffer()
        {
            throw new System.NotImplementedException();
        }

        public ByteBuffer duplicate()
        {
            throw new System.NotImplementedException();
        }

        public byte get()
        {
            throw new System.NotImplementedException();
        }

        public int get(int mInputBuffer)
        {
            throw new System.NotImplementedException();
        }

        public void mark()
        {
            throw new System.NotImplementedException();
        }

        public void reset()
        {
            throw new System.NotImplementedException();
        }

        public long getLong()
        {
            throw new System.NotImplementedException();
        }

        public void putLong(long size)
        {
            throw new System.NotImplementedException();
        }
    }
}