using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace SigningServer.Server.SigningTool
{
    internal class ManifestSection : List<ManifestEntry>
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public string Digest { get; set; }

        public void Read(StreamReader reader)
        {
            string line;
            bool initialEntry = true;
            while ((line = reader.ReadLine()) != null)
            {
                // section end
                if (line == string.Empty)
                {
                    break;
                }

                if (line.StartsWith(" "))
                {
                    var last = this.LastOrDefault();
                    if (last != null)
                    {
                        last.Value += line.Substring(1);
                    }
                    else if(Value != null)
                    {
                        Value += line.Substring(1);
                    }
                    else
                    {
                        throw new MalformedManifestException($"found multiline continue without entry start '{line}'");
                    }
                }
                else
                {
                    var separator = line.IndexOf(":");
                    if (separator == -1)
                    {
                        throw new MalformedManifestException($"missing : separating key and value '{line}'");
                    }

                    var key = line.Substring(0, separator).Trim();
                    var value = line.Substring(separator + 1).Trim();

                    if (initialEntry)
                    {
                        Name = key;
                        Value = value;
                        initialEntry = false;
                    }
                    else
                    {
                        Add(new ManifestEntry
                        {
                            Key = key,
                            Value = value
                        });
                    }
                }
            }
        }

        public void Write(Stream target, HashAlgorithm manifestHasher, AndroidApkSigningTool.HashAlgorithmInfo hashAlgorithmInfo)
        {
            using (var sectionHasher = hashAlgorithmInfo?.HashAlgorithmFactory())
            {
                sectionHasher?.Initialize();

                byte[] writtenData = target.WriteManifestLine($"{Name}: {Value}");

                manifestHasher?.TransformBlock(writtenData, 0, writtenData.Length, null, 0);
                sectionHasher?.TransformBlock(writtenData, 0, writtenData.Length, null, 0);

                foreach (var entry in this)
                {
                    writtenData = target.WriteManifestLine($"{entry.Key}: {entry.Value}");
                    manifestHasher?.TransformBlock(writtenData, 0, writtenData.Length, null, 0);
                    sectionHasher?.TransformBlock(writtenData, 0, writtenData.Length, null, 0);
                }

                target.Write(Manifest.NewLineBytes, 0, Manifest.NewLineBytes.Length);
                manifestHasher?.TransformBlock(Manifest.NewLineBytes, 0, Manifest.NewLineBytes.Length, null, 0);
                sectionHasher?.TransformFinalBlock(Manifest.NewLineBytes, 0, Manifest.NewLineBytes.Length);

                if (sectionHasher != null)
                {
                    Digest = Convert.ToBase64String(sectionHasher.Hash);
                }
            }
        }
    }
}