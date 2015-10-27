using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SigningServer.Server.SigningTool
{
    public class Manifest
    {
        public static readonly byte[] NewLineBytes = Encoding.ASCII.GetBytes(Environment.NewLine);

        public ManifestSection MainSection { get; }
        public Dictionary<string, ManifestSection> AdditionalSections { get; }

        public string Sha256Digest { get; set; }

        public Manifest()
        {
            MainSection = new ManifestSection();
            AdditionalSections = new Dictionary<string, ManifestSection>();
        }

        public void Read(Stream stream)
        {
            var reader = new StreamReader(stream);
            MainSection.Read(reader);

            while (!reader.EndOfStream)
            {
                var section = new ManifestSection();
                section.Read(reader);
                AdditionalSections[section.Value] = section;
            }
        }

        public void Write(Stream stream)
        {
            using (var manifestHasher = new SHA256Managed())
            {
                manifestHasher.Initialize();

                MainSection.Write(stream, manifestHasher);

                foreach (var section in AdditionalSections.Values)
                {
                    section.Write(stream, manifestHasher);
                }

                //stream.Write(NewLineBytes,0, NewLineBytes.Length);
                manifestHasher.TransformFinalBlock(new byte[0], 0, 0);
                Sha256Digest = Convert.ToBase64String(manifestHasher.Hash);
            }
        }
    }
}
