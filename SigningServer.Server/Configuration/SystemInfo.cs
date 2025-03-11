using System.Reflection;
using SigningServer.Server.Controllers;

namespace SigningServer.Server.Configuration;

public class SystemInfo
{
    public const string BaseKey = "SystemInfo";
    
    public string ServiceName { get; set; } = "";
    public string ServiceDescription { get; set; } = "";
    public string SupportLink { get; set; } = "";
    public string KnowledgeBaseLink { get; set; } = "";

    public static readonly string ApplicationVersion = typeof(SystemInfoController).Assembly
                                                           .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                                                           ?.InformationalVersion ??
                                                       typeof(SystemInfoController).Assembly.GetName().Version
                                                           ?.ToString() ??
                                                       "Unknown";
}
