// <auto-generated>
// This code was auto-generated.
// Changes to this file may cause incorrect behavior and will be lost if
// the code is regenerated.
// </auto-generated>

using System;

namespace SigningServer.Android.Com.Android.Apksig.Internal.Jar
{
    /// <summary>
    /// Producer of {@code META-INF/MANIFEST.MF} file.
    /// 
    /// @see &lt;a href="https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#JAR_Manifest"&gt;JAR Manifest format&lt;/a&gt;
    /// </summary>
    public abstract class ManifestWriter
    {
        internal static readonly sbyte[] CRLF = new sbyte[]{
            (sbyte)'\r', (sbyte)'\n'}
        ;
        
        internal static readonly int MAX_LINE_LENGTH = 70;
        
        internal ManifestWriter()
        {
        }
        
        public static void WriteMainSection(SigningServer.Android.IO.OutputStream output, SigningServer.Android.Util.Jar.Attributes attributes)
        {
            string manifestVersion = attributes.GetValue(SigningServer.Android.Util.Jar.Attributes.Name.MANIFEST_VERSION);
            if (manifestVersion == null)
            {
                throw new System.ArgumentException("Mandatory " + SigningServer.Android.Util.Jar.Attributes.Name.MANIFEST_VERSION + " attribute missing");
            }
            SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.WriteAttribute(output, SigningServer.Android.Util.Jar.Attributes.Name.MANIFEST_VERSION, manifestVersion);
            if (attributes.Size() > 1)
            {
                SigningServer.Android.Collections.SortedMap<string, string> namedAttributes = SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.GetAttributesSortedByName(attributes);
                namedAttributes.Remove(SigningServer.Android.Util.Jar.Attributes.Name.MANIFEST_VERSION.ToString());
                SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.WriteAttributes(output, namedAttributes);
            }
            SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.WriteSectionDelimiter(output);
        }
        
        public static void WriteIndividualSection(SigningServer.Android.IO.OutputStream output, string name, SigningServer.Android.Util.Jar.Attributes attributes)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.WriteAttribute(output, "Name", name);
            if (!attributes.IsEmpty())
            {
                SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.WriteAttributes(output, SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.GetAttributesSortedByName(attributes));
            }
            SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.WriteSectionDelimiter(output);
        }
        
        public static void WriteSectionDelimiter(SigningServer.Android.IO.OutputStream output)
        {
            output.Write(SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.CRLF);
        }
        
        public static void WriteAttribute(SigningServer.Android.IO.OutputStream output, SigningServer.Android.Util.Jar.Attributes.Name name, string value)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.WriteAttribute(output, name.ToString(), value);
        }
        
        internal static void WriteAttribute(SigningServer.Android.IO.OutputStream output, string name, string value)
        {
            SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.WriteLine(output, name + ": " + value);
        }
        
        internal static void WriteLine(SigningServer.Android.IO.OutputStream output, string line)
        {
            sbyte[] lineBytes = line.GetBytes(SigningServer.Android.IO.Charset.StandardCharsets.UTF_8);
            int offset = 0;
            int remaining = lineBytes.Length;
            bool firstLine = true;
            while (remaining > 0)
            {
                int chunkLength;
                if (firstLine)
                {
                    chunkLength = SigningServer.Android.Core.Math.Min(remaining, SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.MAX_LINE_LENGTH);
                }
                else 
                {
                    output.Write(SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.CRLF);
                    output.Write(' ');
                    chunkLength = SigningServer.Android.Core.Math.Min(remaining, SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.MAX_LINE_LENGTH - 1);
                }
                output.Write(lineBytes, offset, chunkLength);
                offset += chunkLength;
                remaining -= chunkLength;
                firstLine = false;
            }
            output.Write(SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.CRLF);
        }
        
        public static SigningServer.Android.Collections.SortedMap<string, string> GetAttributesSortedByName(SigningServer.Android.Util.Jar.Attributes attributes)
        {
            SigningServer.Android.Collections.Set<SigningServer.Android.Collections.MapEntry<object, object>> attributesEntries = attributes.EntrySet();
            SigningServer.Android.Collections.SortedMap<string, string> namedAttributes = new SigningServer.Android.Collections.TreeMap<string, string>();
            foreach (SigningServer.Android.Collections.MapEntry<object, object> attribute in attributesEntries)
            {
                string attrName = attribute.GetKey().ToString();
                string attrValue = attribute.GetValue().ToString();
                namedAttributes.Put(attrName, attrValue);
            }
            return namedAttributes;
        }
        
        public static void WriteAttributes(SigningServer.Android.IO.OutputStream output, SigningServer.Android.Collections.SortedMap<string, string> attributesSortedByName)
        {
            foreach (SigningServer.Android.Collections.MapEntry<string, string> attribute in attributesSortedByName.EntrySet())
            {
                string attrName = attribute.GetKey();
                string attrValue = attribute.GetValue();
                SigningServer.Android.Com.Android.Apksig.Internal.Jar.ManifestWriter.WriteAttribute(output, attrName, attrValue);
            }
        }
        
    }
    
}