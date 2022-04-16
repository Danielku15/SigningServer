using System.Collections.Generic;
using SigningServer.Android.Com.Android.Apksig.Internal.Jar;
using SigningServer.Android.IO;

namespace SigningServer.Android.Util.Jar
{
    public class Manifest
    {
        private readonly Attributes mMainAttributes;
        private readonly Dictionary<string, Attributes> mEntries;

        public Manifest()
        {
            mMainAttributes = new Attributes();
            mEntries = new Dictionary<string, Attributes>();
        }

        public Manifest(InputStream stream)
        {
            var ms = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int c;
            while ((c = stream.Read(buf)) > 0)
            {
                ms.Write(buf, 0, c);
            }

            var im = new ManifestParser(ms.ToByteArray());

            ManifestParser.Section manifestMainSection = im.ReadSection();
            mMainAttributes = new Attributes();
            foreach (var attribute in manifestMainSection.GetAttributes())
            {
                mMainAttributes.Put(new Attributes.Name(attribute.GetName()), attribute.GetValue());
            }

            mEntries = new Dictionary<string, Attributes>();
            List<ManifestParser.Section> manifestIndividualSections = im.ReadAllSections();
            foreach (var section in manifestIndividualSections)
            {
                var attributes = new Attributes();
                foreach (var attribute in section.GetAttributes())
                {
                    attributes.Put(new Attributes.Name(attribute.GetName()), attribute.GetValue());
                }

                mEntries[section.GetName() ?? string.Empty] = attributes;
            }
        }

        public Attributes GetMainAttributes()
        {
            return mMainAttributes;
        }
    }
}