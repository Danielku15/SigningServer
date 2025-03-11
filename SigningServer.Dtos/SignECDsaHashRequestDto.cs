namespace SigningServer.Dtos;

public record SignECDsaHashRequestDto(string? Username, string? Password, string Data);