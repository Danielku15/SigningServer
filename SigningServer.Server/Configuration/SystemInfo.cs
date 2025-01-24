namespace SigningServer.Server.Configuration;

public class SystemInfo
{
    public const string BaseKey = "SystemInfo";
    
    public string ServiceName { get; set; } = "";
    public string ServiceDescription { get; set; } = "";
    public string SupportLink { get; set; } = "";
    public string KnowledgeBaseLink { get; set; } = "";
}
