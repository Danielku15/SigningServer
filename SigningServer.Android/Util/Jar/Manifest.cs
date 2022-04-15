using System.Collections.Generic;
using System.IO;
using SigningServer.Android.Com.Android.Apksig.Internal.Jar;
using SigningServer.Android.IO;

namespace SigningServer.Android.Util.Jar
{
    public class Manifest
    {
        private readonly Attributes _mainAttributes;
        private readonly Dictionary<string, Attributes> _entries;
        public Manifest()
        {
            _mainAttributes = new Attributes();
            _entries = new Dictionary<string, Attributes>();
        }

        public Manifest(InputStream stream)
        {
            var ms = new MemoryStream();
            stream.CopyTo(ms);
            var im = new ManifestParser(ms.ToArray());
            
            ManifestParser.Section manifestMainSection = im.ReadSection();
            _mainAttributes = new Attributes();
            foreach (var attribute in manifestMainSection.GetAttributes())
            {
                _mainAttributes[attribute.GetName()] = attribute.GetValue();
            }

            _entries = new Dictionary<string, Attributes>();
            List<ManifestParser.Section> manifestIndividualSections = im.ReadAllSections();
            foreach (var section in manifestIndividualSections)
            {
                var attributes = new Attributes();
                foreach (var attribute in section.GetAttributes())
                {
                    attributes[attribute.GetName()] = attribute.GetValue();
                }

                _entries[section.GetName()] = attributes;
            }
        }

        public Attributes GetMainAttributes()
        {
            return _mainAttributes;
        }

    }
}