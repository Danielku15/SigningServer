using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using SigningServer.Server.Configuration;
using SigningServer.Server.Dtos;

namespace SigningServer.Server.Controllers;

[ApiController]
[Route("system")]
public class SystemInfoController : Controller
{
    private readonly IOptionsMonitor<SystemInfo> _systemInfo;
    private readonly IUsageReportProvider _usageReportProvider;

    public SystemInfoController(IOptionsMonitor<SystemInfo> systemInfo, IUsageReportProvider usageReportProvider)
    {
        _systemInfo = systemInfo;
        _usageReportProvider = usageReportProvider;
    }

    public ActionResult<SystemInfoDto> GetSystemInfo()
    {
        var value = _systemInfo.CurrentValue;
        return Ok(new SystemInfoDto
        {
            ApplicationVersion = SystemInfo.ApplicationVersion,
            ServiceName = value.ServiceName,
            ServiceDescription = value.ServiceDescription,
            SupportLink = value.SupportLink,
            KnowledgeBaseLink = value.KnowledgeBaseLink,
        });
    }

    [HttpGet("usage-reports")]
    public async Task<ActionResult> GetUsageReports(CancellationToken cancellationToken)
    {
        return File(await _usageReportProvider.GetUsageReportExcelAsync(cancellationToken),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            $"{DateTime.Now:yyyyMMddHHmmss}_SigningServerUsageReport.xlsx");
    }
}
