using System.Collections;
using System.Collections.Generic;
using System.IO;
using SigningServer.Android.ApkSig.Internal.Jar;

namespace SigningServer.Android
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

        public Manifest(Stream stream)
        {
            var ms = new MemoryStream();
            stream.CopyTo(ms);
            var im = new ManifestParser(ms.ToArray());
            
            ManifestParser.Section manifestMainSection = im.readSection();
            _mainAttributes = new Attributes();
            foreach (var attribute in manifestMainSection.getAttributes())
            {
                _mainAttributes[attribute.getName()] = attribute.getValue();
            }

            _entries = new Dictionary<string, Attributes>();
            List<ManifestParser.Section> manifestIndividualSections = im.readAllSections();
            foreach (var section in manifestIndividualSections)
            {
                var attributes = new Attributes();
                foreach (var attribute in section.getAttributes())
                {
                    attributes[attribute.getName()] = attribute.getValue();
                }

                _entries[section.getName()] = attributes;
            }
        }

        public Attributes getMainAttributes()
        {
            return _mainAttributes;
        }

    }
}