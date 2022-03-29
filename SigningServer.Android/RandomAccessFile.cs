namespace SigningServer.Android
{
    public class RandomAccessFile
    {
        public FileChannel getChannel()
        {
            throw new System.NotImplementedException();
        }

        public void seek(long mPosition)
        {
            throw new System.NotImplementedException();
        }

        public void write(byte[] buf, int offset, int length)
        {
            throw new System.NotImplementedException();
        }
    }

    public class FileChannel
    {
        public long size()
        {
            throw new System.NotImplementedException();
        }

        public void position(long chunkOffsetInFile)
        {
            throw new System.NotImplementedException();
        }

        public int read(ByteBuffer buf)
        {
            throw new System.NotImplementedException();
        }

        public void write(ByteBuffer buf)
        {
            throw new System.NotImplementedException();
        }
    }
}