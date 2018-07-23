/*
 * Copyright (C) 2016 The Android Open Source Project
 * Copyright (C) 2018 Daniel Kuschny (C# port based on oreo-master)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.IO;

namespace SigningServer.Android.Util
{
    public class DataSource : IDisposable
    {
        private const int MaxReadChunkSize = 65536;

        private readonly long _start;
        private readonly Stream _stream;
        private readonly BinaryReader _reader;
        public long Length { get; }

        public DataSource(Stream stream)
        : this(stream, 0, stream.Length)
        {
        }

        public long Position
        {
            get => _stream.Position - _start;
            set => _stream.Position = _start + value;
        }

        public long Remaining => Length - Position;

        private DataSource(Stream stream, long start, long length)
        {
            _stream = stream;
            _start = start;
            Length = length;
            _reader = new BinaryReader(stream);
        }


        public void Dispose()
        {
            _stream?.Dispose();
        }

        public byte[] GetByteBuffer(long offset, long size)
        {
            var buf = new byte[size];
            _stream.Seek(_start + offset, SeekOrigin.Begin);
            _stream.Read(buf, 0, (int)size);
            return buf;
        }

        public DataSource Slice(long offset, long size)
        {
            if (offset == 0 && size == Length) return this;
            return new DataSource(_stream, _start + offset, size);
        }

        public int ReadInt32()
        {
            return _reader.ReadInt32();
        }

        public short ReadInt16()
        {
            return _reader.ReadInt16();
        }

        public int ReadUInt16()
        {
            return _reader.ReadUInt16();
        }

        public long ReadUInt32()
        {
            return _reader.ReadUInt32();
        }

        public void Feed(long offset, long size, Stream output)
        {
            var chunkOffsetInFile = _start + offset;
            var remaining = size;
            var buf = new byte[(int)Math.Min(remaining, MaxReadChunkSize)];
            while (remaining > 0)
            {
                var chunkSize = (int)Math.Min(remaining, buf.Length);
                lock (_stream)
                {
                    _stream.Seek(chunkOffsetInFile, SeekOrigin.Begin);
                    _stream.Read(buf, 0, chunkSize);
                }
                output.Write(buf, 0, chunkSize);
                chunkOffsetInFile += chunkSize;
                remaining -= chunkSize;
            }
            output.Flush();
        }
    }
}
