using System.Security.Cryptography;
using System.Text.Json.Serialization;
using SigningServer.Core;
using SigningServer.Dtos;

namespace SigningServer.Client;

[JsonSourceGenerationOptions(WriteIndented = false, PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(ServerCapabilitiesResponse))]
[JsonSerializable(typeof(ServerSupportedFormat))]
[JsonSerializable(typeof(RSASignaturePaddingMode))]
[JsonSerializable(typeof(SignHashRequestDto))]
[JsonSerializable(typeof(SignHashResponseDto))]
[JsonSerializable(typeof(SignHashResponseStatus))]
[JsonSerializable(typeof(LoadCertificateRequestDto))]
[JsonSerializable(typeof(LoadCertificateFormat))]
[JsonSerializable(typeof(LoadCertificateResponseDto))]
[JsonSerializable(typeof(LoadCertificateResponseStatus))]
public partial class DtoJsonSerializerContext : JsonSerializerContext
{
}
