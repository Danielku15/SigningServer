using System;

namespace SigningServer.Android.IO
{
    public abstract class Buffer
    {
        protected readonly int mCapacity;

        protected int mMark = -1;
        protected int mPosition;
        protected int mLimit;

        public int Capacity()
        {
            return mCapacity;
        }

        public int Limit()
        {
            return mLimit;
        }

        protected Buffer(int mark, int pos, int lim, int cap)
        {
            // package-private
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
            String msg = null;

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
    }
}