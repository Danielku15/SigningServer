using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using SigningServer.Core;

namespace SigningServer.ClientCore;

/// <summary>
/// Represents the signing client 
/// </summary>
public class SigningClientConfigurationBase
{
    /// <summary>
    /// Whether to overwrite existing signatures or fail when signatures are present.
    /// </summary>
    public bool OverwriteSignatures { get; set; }

    /// <summary>
    /// Whether to ignore any existing signatures and not sign in this case.
    /// </summary>
    public bool IgnoreExistingSignatures { get; set; } = true;

    /// <summary>
    /// Whether to ignore unsupported file formats or whether to fail when encountering them. 
    /// </summary>
    public bool IgnoreUnsupportedFiles { get; set; } = true;

    /// <summary>
    /// The timeout of signing operations in seconds.
    /// </summary>
    public int Timeout { get; set; } = 60;

    /// <summary>
    /// The hash algorithm to use.
    /// </summary>
    public string? HashAlgorithm { get; set; }
    
    /// <summary>
    /// The RSA signature padding mode to use in case of RSA Hashing.
    /// </summary>
    public RSASignaturePaddingMode? RsaSignaturePaddingMode { get; set; }
    
    /// <summary>
    /// The number of retries the client should perform before giving up failed sign operations.
    /// </summary>
    public int Retry { get; set; } = 3;

    /// <summary>
    /// The number of parallel signing operations to perform.
    /// </summary>
    public int? Parallel { get; set; } = 1;

    /// <summary>
    /// If this extension is set, the files will be hashed locally and the hash is sent to the server
    /// for signing. The hash will be written raw-byte encoded to a file with this file extension (at the input file location).
    /// </summary>
    public string? SignHashFileExtension { get; set; }

    /// <summary>
    /// The sources (files and directories) to sign.
    /// </summary>
    [JsonIgnore]
    public IList<string> Sources { get; set; } = new List<string>();

    /// <summary>
    /// If a certificate download should be performed, the path to write it to.
    /// </summary>
    public string? LoadCertificatePath { get; set; }

    /// <summary>
    /// If a certificate download should be performed, whether to load the whole chain instead of only the cert used
    /// for signing.
    /// </summary>
    public bool LoadCertificateChain { get; set; }

    /// <summary>
    /// If a certificate download should be performed, the format to download.
    /// </summary>
    public LoadCertificateFormat? LoadCertificateExportFormat { get; set; }

    public virtual bool FillFromArgs(string[] args, ILogger log)
    {
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg.StartsWith("-"))
            {
                if (!HandleArg(log, arg.ToLowerInvariant(), args, ref i))
                {
                    return false;
                }
            }
            else
            {
                arg = arg.Trim('"');
                if (File.Exists(arg) || Directory.Exists(arg))
                {
                    Sources.Add(arg);
                }
                else
                {
                    log.LogError("Config could not be loaded: File or Directory not found '{file}'", arg);
                    return false;
                }
            }
        }

        return true;
    }

    protected virtual bool HandleArg(ILogger log, string arg, string[] args, ref int i)
    {
        switch (arg)
        {
            case "-h":
            case "--hash-algorithm":
                if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                {
                    i++;
                    HashAlgorithm = args[i];
                }
                else
                {
                    HashAlgorithm = "";
                }

                return true;
            case "--rsa-signature-padding":
                if (i + 1 < args.Length)
                {
                    i++;
                    
                    if (!Enum.TryParse(typeof(RSASignaturePaddingMode), args[i], true, out var p) ||
                        p is not RSASignaturePaddingMode contentType)
                    {
                        log.LogError("Config could not be loaded: Invalid RSA Signature Padding");
                        return false;
                    }

                    RsaSignaturePaddingMode = contentType;
                }
                else
                {
                    log.LogError("Config could not be loaded: No RSA Signature Padding provided");
                    return false;
                }
                return true;
            case "-os":
            case "--overwrite-signatures":
                OverwriteSignatures = true;
                return true;
            case "-ks":
            case "--keep-signatures":
                OverwriteSignatures = false;
                return true;
            case "-is":
            case "--ignore-existing-signatures":
                IgnoreExistingSignatures = true;
                return true;
            case "-fs":
            case "--fail-on-existing-signatures":
                IgnoreExistingSignatures = false;
                return true;
            case "-iu":
            case "--ignore-unsupported-files":
                IgnoreUnsupportedFiles = true;
                return true;
            case "-fu":
            case "--fail-on-unsupported-files":
                IgnoreUnsupportedFiles = false;
                return true;
            case "-t":
            case "--timeout":
                if (i + 1 < args.Length)
                {
                    if (int.TryParse(args[i + 1], out var v))
                    {
                        Timeout = v;
                    }
                    else
                    {
                        log.LogError("Config could not be loaded: Invalid timeout value provided");
                        return false;
                    }

                    i++;
                }
                else
                {
                    log.LogError("Config could not be loaded: No timeout value provided");
                    return false;
                }

                return true;
            case "--sign-hash":
                if (i + 1 < args.Length)
                {
                    i++;
                    SignHashFileExtension = args[i];
                    if (!SignHashFileExtension.StartsWith("."))
                    {
                        SignHashFileExtension = "." + SignHashFileExtension;
                    }

                    if (string.IsNullOrEmpty(HashAlgorithm))
                    {
                        HashAlgorithm = "SHA256";
                    }
                }
                else
                {
                    log.LogError("Config could not be loaded: No signature file extension value provided");
                    return false;
                }

                return true;
            case "--load-certificate":
                if (i + 2 < args.Length)
                {
                    i++;
                    if (!Enum.TryParse(typeof(LoadCertificateFormat), args[i], true, out var p) ||
                        p is not LoadCertificateFormat contentType)
                    {
                        log.LogError("Config could not be loaded: Invalid certificate format");
                        return false;
                    }

                    LoadCertificateExportFormat = contentType;
                    i++;
                    LoadCertificatePath = Path.GetFullPath(args[i]);
                }
                else
                {
                    log.LogError("Config could not be loaded: No signature file extension value provided");
                    return false;
                }

                return true;
            case "--load-certificate-chain":
                if (i + 2 < args.Length)
                {
                    i++;
                    if (!Enum.TryParse(typeof(LoadCertificateFormat), args[i], true, out var p) ||
                        p is not LoadCertificateFormat contentType)
                    {
                        log.LogError("Config could not be loaded: Invalid certificate format");
                        return false;
                    }

                    LoadCertificateExportFormat = contentType;
                    i++;
                    LoadCertificatePath = Path.GetFullPath(args[i]);
                    LoadCertificateChain = true;
                }
                else
                {
                    log.LogError("Config could not be loaded: No signature file extension value provided");
                    return false;
                }

                return true;
            default:
                log.LogError("Unknown option '{file}'", arg);
                return false;
        }
    }

    public static void PrintUsage(TextWriter writer)
    {
        Console.WriteLine("options: ");

        Console.WriteLine("  --help, -h");
        Console.WriteLine("      Print this help.");

        Console.WriteLine("  --config File, -c File");
        Console.WriteLine("      The path to the config.json to use (overwrites any previously provided settings)");

        writer.WriteLine("  --hash-algorithm [algorithm], -h [algorithm]");
        writer.WriteLine("      The Hash Algorithm to use for signing (empty for default)");
        writer.WriteLine("      Config.json Key: \"HashAlgorithm\": \"value\"");

        writer.WriteLine("  --rsa-signature-padding [algorithm]");
        writer.WriteLine("      The RSA Signature Padding to use for signing (empty for default)");
        writer.WriteLine("      Config.json Key: \"RsaSignaturePaddingMode\": \"value\"");

        writer.WriteLine("  --overwrite-signatures, -os");
        writer.WriteLine("      Enable overwriting of existing signatures");
        writer.WriteLine("      Config.json Key: \"OverwriteSignatures\": true");

        writer.WriteLine("  --keep-signatures, -ks");
        writer.WriteLine("      Disable overwriting of existing signatures");
        writer.WriteLine("      Config.json Key: \"OverwriteSignatures\": false");

        writer.WriteLine("  --ignore-existing-signatures, -is");
        writer.WriteLine("      Ignore existing signatures");
        writer.WriteLine("      Config.json Key: \"IgnoreExistingSignatures\": true");

        writer.WriteLine("  --fail-on-existing-signatures, -fs");
        writer.WriteLine("      Whether to fail with existing signatures");
        writer.WriteLine("      Config.json Key: \"IgnoreExistingSignatures\": false");

        writer.WriteLine("  --ignore-unsupported-files, -iu");
        writer.WriteLine("      Whether to ignore unsupported file formats");
        writer.WriteLine("      Config.json Key: \"IgnoreUnsupportedFiles\": true");

        writer.WriteLine("  --fail-on-unsupported-files, -fu");
        writer.WriteLine("      Whether to fail when unsupported file formats");
        writer.WriteLine("      Config.json Key: \"IgnoreUnsupportedFiles\": false");

        writer.WriteLine("  --timeout Timeout, -t Timeout");
        writer.WriteLine("      Configures the timeout in seconds before failing the signing operations.");
        writer.WriteLine("      Config.json Key: \"IgnoreUnsupportedFiles\": 300");

        writer.WriteLine("  --retries Retries, -re Retries");
        writer.WriteLine(
            "      The number of retries to attempt on potentially recoverable errors (e.g. timeouts).");
        writer.WriteLine("      Config.json Key: \"Retry\": 3");

        writer.WriteLine("  --parallel [NumberOfThreads], -pa [NumberOfThreads]");
        writer.WriteLine("      The number of parallel signing operations the client should perform.");
        writer.WriteLine("      Might be reduced based on the server configuration.");
        writer.WriteLine("      Leave value empty (or null in config.json) for auto detection.");
        writer.WriteLine("      Config.json Key: \"Parallel\": 4");

        writer.WriteLine("  --sign-hash SignatureExtension");
        writer.WriteLine("      Instead of uploading the file and signing it according to the known file");
        writer.WriteLine("      format. The file will be hashed locally, and the hash is sent to the ");
        writer.WriteLine("      server for signing. The signature will be written as raw bytes to the");
        writer.WriteLine(
            "      same paths as the input file with the extension changed to the provided file extension");

        writer.WriteLine("  --load-certificate Format Path");
        writer.WriteLine(
            "      Instead of signing files a certificate file containing the public key will be downloaded");
        writer.WriteLine("      to the specified path. Can be combined with other operations");
        writer.WriteLine("      Format: ");
        writer.WriteLine(
            "        - \"PemCertificate\" - A PEM encoded file holding full X509 certificates (BEGIN/END CERTIFICATE)");
        writer.WriteLine(
            "        - \"PemPublicKey\" - A PEM encoded file holding Public Key Subject Infos  (BEGIN/END PUBLIC KEY)");
        writer.WriteLine("        - \"Pkcs12\" - A Pkcs12 encoded file (aka. PFX).");

        writer.WriteLine("  --load-certificate-chain Format");
        writer.WriteLine("      Like --load-certificate but the whole certificate chian will be downloaded.");

        writer.WriteLine();

        writer.WriteLine("sources: ");
        writer.WriteLine("   Can be any single file or a full directory (recursive) to sign.");
        writer.WriteLine("   For directories only known supported files are considered.");
        writer.WriteLine();
        
        Console.WriteLine("exit codes: ");
        Console.WriteLine("   1 - unexpected error");
        Console.WriteLine("   2 - Specified source could not be found");
        Console.WriteLine(
            "   3 - Detected a file which is already signed and --fail-on-existing-signatures is set");
        Console.WriteLine("   4 - Detected an unsupported file format and --fail-on-unsupported-files is active");
        Console.WriteLine("   5 - Unauthorized, wrong username or password");
        Console.WriteLine("   6 - Client configuration invalid");
        Console.WriteLine("   7 - Communication error");
    }
}
