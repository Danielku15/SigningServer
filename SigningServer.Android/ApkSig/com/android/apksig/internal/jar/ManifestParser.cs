// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Jar
{
    /// <summary>
    /// JAR manifest and signature file parser.
    /// 
    /// &lt;p&gt;These files consist of a main section followed by individual sections. Individual sections
    /// are named, their names referring to JAR entries.
    /// 
    /// @see &lt;a href="https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#JAR_Manifest"&gt;JAR Manifest format&lt;/a&gt;
    /// </summary>
    public class ManifestParser
    {
        internal readonly sbyte[] mManifest;
        
        internal int mOffset;
        
        internal int mEndOffset;
        
        internal sbyte[] mBufferedLine;
        
        /// <summary>
        /// Constructs a new {@code ManifestParser} with the provided input.
        /// </summary>
        public ManifestParser(sbyte[] data)
            : this (data, 0, data.Length)
        {
        }
        
        /// <summary>
        /// Constructs a new {@code ManifestParser} with the provided input.
        /// </summary>
        public ManifestParser(sbyte[] data, int offset, int length)
        {
            mManifest = data;
            mOffset = offset;
            mEndOffset = offset + length;
        }
        
        /// <summary>
        /// Returns the remaining sections of this file.
        /// </summary>
        public virtual SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Section> ReadAllSections()
        {
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Section> sections = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Section>();
            SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Section section;
            while ((section = ReadSection()) != null)
            {
                sections.Add(section);
            }
            return sections;
        }
        
        /// <summary>
        /// Returns the next section from this file or {@code null} if end of file has been reached.
        /// </summary>
        public virtual SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Section ReadSection()
        {
            int sectionStartOffset;
            string attr;
            do
            {
                sectionStartOffset = mOffset;
                attr = ReadAttribute();
                if (attr == null)
                {
                    return null;
                }
            }
            while (attr.Length() == 0);
            SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Attribute> attrs = new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Attribute>();
            attrs.Add(SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.ParseAttr(attr));
            while (true)
            {
                attr = ReadAttribute();
                if ((attr == null) || (attr.Length() == 0))
                {
                    break;
                }
                attrs.Add(SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.ParseAttr(attr));
            }
            int sectionEndOffset = mOffset;
            int sectionSizeBytes = sectionEndOffset - sectionStartOffset;
            return new SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Section(sectionStartOffset, sectionSizeBytes, attrs);
        }
        
        internal static SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Attribute ParseAttr(string attr)
        {
            int delimiterIndex = attr.IndexOf(": ");
            if (delimiterIndex == -1)
            {
                return new SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Attribute(attr, "");
            }
            else 
            {
                return new SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Attribute(attr.SubstringIndex(0, delimiterIndex), attr.SubstringIndex(delimiterIndex + ": ".Length()));
            }
        }
        
        /// <summary>
        /// Returns the next attribute or empty {@code String} if end of section has been reached or
        /// {@code null} if end of input has been reached.
        /// </summary>
        internal string ReadAttribute()
        {
            sbyte[] bytes = ReadAttributeBytes();
            if (bytes == null)
            {
                return null;
            }
            else if (bytes.Length == 0)
            {
                return "";
            }
            else 
            {
                return SigningServer.Android.Core.StringExtensions.Create(bytes, SigningServer.Android.IO.Charset.StandardCharsets.UTF_8);
            }
        }
        
        /// <summary>
        /// Returns the next attribute or empty array if end of section has been reached or {@code null}
        /// if end of input has been reached.
        /// </summary>
        internal sbyte[] ReadAttributeBytes()
        {
            if ((mBufferedLine != null) && (mBufferedLine.Length == 0))
            {
                mBufferedLine = null;
                return SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.EMPTY_BYTE_ARRAY;
            }
            sbyte[] line = ReadLine();
            if (line == null)
            {
                if (mBufferedLine != null)
                {
                    sbyte[] result = mBufferedLine;
                    mBufferedLine = null;
                    return result;
                }
                return null;
            }
            if (line.Length == 0)
            {
                if (mBufferedLine != null)
                {
                    sbyte[] result = mBufferedLine;
                    mBufferedLine = SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.EMPTY_BYTE_ARRAY;
                    return result;
                }
                return SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.EMPTY_BYTE_ARRAY;
            }
            sbyte[] attrLine;
            if (mBufferedLine == null)
            {
                attrLine = line;
            }
            else 
            {
                if ((line.Length == 0) || (line[0] != ' '))
                {
                    sbyte[] result = mBufferedLine;
                    mBufferedLine = line;
                    return result;
                }
                attrLine = mBufferedLine;
                mBufferedLine = null;
                attrLine = SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Concat(attrLine, line, 1, line.Length - 1);
            }
            while (true)
            {
                line = ReadLine();
                if (line == null)
                {
                    return attrLine;
                }
                else if (line.Length == 0)
                {
                    mBufferedLine = SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.EMPTY_BYTE_ARRAY;
                    return attrLine;
                }
                if (line[0] == ' ')
                {
                    attrLine = SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Concat(attrLine, line, 1, line.Length - 1);
                }
                else 
                {
                    mBufferedLine = line;
                    return attrLine;
                }
            }
        }
        
        internal static readonly sbyte[] EMPTY_BYTE_ARRAY = new sbyte[0];
        
        internal static sbyte[] Concat(sbyte[] arr1, sbyte[] arr2, int offset2, int length2)
        {
            sbyte[] result = new sbyte[arr1.Length + length2];
            SigningServer.Android.Core.System.Arraycopy(arr1, 0, result, 0, arr1.Length);
            SigningServer.Android.Core.System.Arraycopy(arr2, offset2, result, arr1.Length, length2);
            return result;
        }
        
        /// <summary>
        /// Returns the next line (without line delimiter characters) or {@code null} if end of input has
        /// been reached.
        /// </summary>
        internal sbyte[] ReadLine()
        {
            if (mOffset >= mEndOffset)
            {
                return null;
            }
            int startOffset = mOffset;
            int newlineStartOffset = -1;
            int newlineEndOffset = -1;
            for (int i = startOffset;i < mEndOffset;i++)
            {
                sbyte b = mManifest[i];
                if (b == '\r')
                {
                    newlineStartOffset = i;
                    int nextIndex = i + 1;
                    if ((nextIndex < mEndOffset) && (mManifest[nextIndex] == '\n'))
                    {
                        newlineEndOffset = nextIndex + 1;
                        break;
                    }
                    newlineEndOffset = nextIndex;
                    break;
                }
                else if (b == '\n')
                {
                    newlineStartOffset = i;
                    newlineEndOffset = i + 1;
                    break;
                }
            }
            if (newlineStartOffset == -1)
            {
                newlineStartOffset = mEndOffset;
                newlineEndOffset = mEndOffset;
            }
            mOffset = newlineEndOffset;
            if (newlineStartOffset == startOffset)
            {
                return SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.EMPTY_BYTE_ARRAY;
            }
            return SigningServer.Android.Collections.Arrays.CopyOfRange(mManifest, startOffset, newlineStartOffset);
        }
        
        /// <summary>
        /// Attribute.
        /// </summary>
        public class Attribute
        {
            internal readonly string mName;
            
            internal readonly string mValue;
            
            /// <summary>
            /// Constructs a new {@code Attribute} with the provided name and value.
            /// </summary>
            public Attribute(string name, string value)
            {
                mName = name;
                mValue = value;
            }
            
            /// <summary>
            /// Returns this attribute's name.
            /// </summary>
            public virtual string GetName()
            {
                return mName;
            }
            
            /// <summary>
            /// Returns this attribute's value.
            /// </summary>
            public virtual string GetValue()
            {
                return mValue;
            }
            
        }
        
        /// <summary>
        /// Section.
        /// </summary>
        public class Section
        {
            internal readonly int mStartOffset;
            
            internal readonly int mSizeBytes;
            
            internal readonly string mName;
            
            internal readonly SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Attribute> mAttributes;
            
            /// <summary>
            /// Constructs a new {@code Section}.
            /// 
            /// @param startOffset start offset (in bytes) of the section in the input file
            /// @param sizeBytes size (in bytes) of the section in the input file
            /// @param attrs attributes contained in the section
            /// </summary>
            public Section(int startOffset, int sizeBytes, SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Attribute> attrs)
            {
                mStartOffset = startOffset;
                mSizeBytes = sizeBytes;
                string sectionName = null;
                if (!attrs.IsEmpty())
                {
                    SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Attribute firstAttr = attrs.Get(0);
                    if ("Name".EqualsIgnoreCase(firstAttr.GetName()))
                    {
                        sectionName = firstAttr.GetValue();
                    }
                }
                mName = sectionName;
                mAttributes = SigningServer.Android.Util.Collections.UnmodifiableList(new SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Attribute>(attrs));
            }
            
            public virtual string GetName()
            {
                return mName;
            }
            
            /// <summary>
            /// Returns the offset (in bytes) at which this section starts in the input.
            /// </summary>
            public virtual int GetStartOffset()
            {
                return mStartOffset;
            }
            
            /// <summary>
            /// Returns the size (in bytes) of this section in the input.
            /// </summary>
            public virtual int GetSizeBytes()
            {
                return mSizeBytes;
            }
            
            /// <summary>
            /// Returns this section's attributes, in the order in which they appear in the input.
            /// </summary>
            public virtual SigningServer.Android.Collections.List<SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Attribute> GetAttributes()
            {
                return mAttributes;
            }
            
            /// <summary>
            /// Returns the value of the specified attribute in this section or {@code null} if this
            /// section does not contain a matching attribute.
            /// </summary>
            public virtual string GetAttributeValue(SigningServer.Android.Util.Jar.Attributes.Name name)
            {
                return GetAttributeValue(name.ToString());
            }
            
            /// <summary>
            /// Returns the value of the specified attribute in this section or {@code null} if this
            /// section does not contain a matching attribute.
            /// 
            /// @param name name of the attribute. Attribute names are case-insensitive.
            /// </summary>
            public virtual string GetAttributeValue(string name)
            {
                foreach (SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestParser.Attribute attr in mAttributes)
                {
                    if (attr.GetName().EqualsIgnoreCase(name))
                    {
                        return attr.GetValue();
                    }
                }
                return null;
            }
            
        }
        
    }
    
}
