namespace SigningServer.Server.Dtos;

public class SystemInfoDto
{
    public string ApplicationVersion { get; set; } = "";
    public string ServiceName { get; set; } = "";
    public string ServiceDescription { get; set; } = "";
    public string SupportLink { get; set; } = "";
    public string KnowledgeBaseLink { get; set; } = "";
}
