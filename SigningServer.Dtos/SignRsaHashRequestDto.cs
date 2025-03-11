using System.Security.Cryptography;

namespace SigningServer.Dtos;

public record SignRsaHashRequestDto(string? Username, string? Password, 
    string Data,
    RSASignaturePaddingMode RsaPadding);
