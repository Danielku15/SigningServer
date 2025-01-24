using System.Data;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using ClosedXML.Excel;

namespace SigningServer.Server;

public interface IUsageReportProvider
{
    Task<byte[]> GetUsageReportExcelAsync(CancellationToken cancellationToken);
}

public class UsageReportProvider(ISigningRequestTracker signingRequestTracker) : IUsageReportProvider
{
    public async Task<byte[]> GetUsageReportExcelAsync(CancellationToken cancellationToken)
    {
        var files = await signingRequestTracker.LoadAllTrackingFiles(cancellationToken);
        using var workbook = new XLWorkbook();
        var worksheet = workbook.Worksheets.Add("Usage");

        using var dataTable = new DataTable();

        dataTable.Columns.Add(new DataColumn("Date", typeof(System.DateTime)));
        dataTable.Columns.Add(new DataColumn("UserInfo"));
        dataTable.Columns.Add(new DataColumn("TotalNumberOfRequests", typeof(ulong)));
        dataTable.Columns.Add(new DataColumn("TotalNumberOfSignaturesCreated", typeof(ulong)));
        dataTable.Columns.Add(new DataColumn("TotalNumberOfSignaturesSkipped", typeof(ulong)));

        foreach (var file in files)
        {
            foreach (var entry in file.Entries)
            {
                var row = dataTable.NewRow();

                row[0] = file.Date;
                row[1] = entry.Value.UserInfo;
                row[2] = entry.Value.TotalNumberOfRequests;
                row[3] = entry.Value.TotalNumberOfSignaturesCreated;
                row[4] = entry.Value.TotalNumberOfSignaturesSkipped;

                dataTable.Rows.Add(row);
            }
        }

        worksheet.FirstCell().InsertTable(dataTable, "Usage", true);
        using var stream = new MemoryStream();
        workbook.SaveAs(stream);

        return stream.ToArray();
    }
}
