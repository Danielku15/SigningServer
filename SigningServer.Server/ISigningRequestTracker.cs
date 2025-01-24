using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SigningServer.Core;
using SigningServer.Server.Configuration;

namespace SigningServer.Server;

/// <summary>
/// Represents the data model behind the singing request tracking logs where
/// an aggregated information of requests are stored daily.
/// </summary>
public class SigningRequestTrackingLogFile
{
    public DateTime Date { get; set; }
    public ConcurrentDictionary<string, SigningRequestTrackingLogFileEntry> Entries { get; set; } = new();

    public void TrackRequest(string userInfo, SignFileResponseStatus status, int numberOfSignatures)
    {
        var userEntry = Entries.GetOrAdd(userInfo,
            _ => new SigningRequestTrackingLogFileEntry { UserInfo = userInfo });

        ulong totalNumberOfSignaturesCreated;
        ulong totalNumberOfSignaturesSkipped;
        switch (status)
        {
            case SignFileResponseStatus.FileSigned:
            case SignFileResponseStatus.FileResigned:
                totalNumberOfSignaturesCreated = (ulong)numberOfSignatures;
                totalNumberOfSignaturesSkipped = 0ul;
                break;
            case SignFileResponseStatus.FileAlreadySigned:
            case SignFileResponseStatus.FileNotSignedUnsupportedFormat:
            case SignFileResponseStatus.FileNotSignedError:
            case SignFileResponseStatus.FileNotSignedUnauthorized:
                totalNumberOfSignaturesSkipped = (ulong)numberOfSignatures;
                totalNumberOfSignaturesCreated = 0ul;
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }

        userEntry.Track(totalNumberOfSignaturesCreated, totalNumberOfSignaturesSkipped);
    }
}

/// <summary>
/// Represents the signing information of one specific user.
/// </summary>
public class SigningRequestTrackingLogFileEntry
{
    private ulong _totalNumberOfRequests;
    private ulong _totalNumberOfSignaturesCreated;
    private ulong _totalNumberOfSignaturesSkipped;
    public string UserInfo { get; set; } = "";

    public ulong TotalNumberOfRequests
    {
        get => _totalNumberOfRequests;
        set => _totalNumberOfRequests = value;
    }

    public ulong TotalNumberOfSignaturesCreated
    {
        get => _totalNumberOfSignaturesCreated;
        set => _totalNumberOfSignaturesCreated = value;
    }

    public ulong TotalNumberOfSignaturesSkipped
    {
        get => _totalNumberOfSignaturesSkipped;
        set => _totalNumberOfSignaturesSkipped = value;
    }

    public void Track(
        ulong totalNumberOfSignaturesCreated,
        ulong totalNumberOfSignaturesSkipped)
    {
        Interlocked.Increment(ref _totalNumberOfRequests);
        Interlocked.Add(ref _totalNumberOfSignaturesCreated, totalNumberOfSignaturesCreated);
        Interlocked.Add(ref _totalNumberOfSignaturesSkipped, totalNumberOfSignaturesSkipped);
    }
}

public interface ISigningRequestTracker
{
    Task TrackRequestAsync(
        string userInfo,
        SignFileResponseStatus status, int numberOfSignatures
    );

    Task<IList<SigningRequestTrackingLogFile>> LoadAllTrackingFiles(CancellationToken cancellationToken);
}

/// <summary>
/// A signing request tracker that persists the tracking data to disk via a background worker.
/// It keeps an in-memory cache and is flushed regularly as configured.
/// </summary>
public class DiskPersistingSigningRequestTracker : ISigningRequestTracker, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true, Converters = { new JsonStringEnumConverter() }
    };

    private readonly SemaphoreSlim _currentDayLock = new(1, 1);
    private SigningRequestTrackingLogFile? _currentDay;


    private readonly ILogger<DiskPersistingSigningRequestTracker> _logger;
    private readonly SigningServerConfiguration _configuration;
    private CancellationTokenSource _backgroundWorkerCancellation = new();
    private Task? _backgroundWorker;

    public DiskPersistingSigningRequestTracker(ILogger<DiskPersistingSigningRequestTracker> logger,
        SigningServerConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
        LoadCurrentDay();
        StartBackgroundFlushWorker();
    }

    private void StartBackgroundFlushWorker()
    {
        _backgroundWorkerCancellation = new CancellationTokenSource();
        _backgroundWorker = Task.Run(() => BackgroundFlushLoop(_backgroundWorkerCancellation.Token));
    }

    private async Task BackgroundFlushLoop(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(_configuration.AuditFlushInterval, token);
                await FlushToDisk(await GetCurrentDay(true, token), token);
            }
        }
        finally
        {
            using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            await FlushToDisk(await GetCurrentDay(true, shutdown.Token), shutdown.Token);
        }
    }

    private async Task FlushToDisk(SigningRequestTrackingLogFile file, CancellationToken token)
    {
        var fileName = GetFileName(file.Date);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);
            var text = JsonSerializer.Serialize(file, JsonOptions);
            await File.WriteAllTextAsync(fileName, text, token);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Failed to flush signing request tracking log file {FileName}", fileName);
        }
    }

    private async Task<SigningRequestTrackingLogFile> GetCurrentDay(bool updateToCurrentDayIfNeeded,
        CancellationToken token)
    {
        await _currentDayLock.WaitAsync(token);
        try
        {
            if (_currentDay == null)
            {
                _currentDay = new SigningRequestTrackingLogFile { Date = DateTime.UtcNow.Date };
            }
            else if (updateToCurrentDayIfNeeded && DateTime.UtcNow.Date > _currentDay.Date)
            {
                await FlushToDisk(_currentDay, token);
                _currentDay = new SigningRequestTrackingLogFile { Date = DateTime.UtcNow };
            }

            return _currentDay;
        }
        finally
        {
            _currentDayLock.Release();
        }
    }

    private void LoadCurrentDay()
    {
        var date = DateTime.UtcNow.Date;
        var fileName = GetFileName(date);
        if (!File.Exists(fileName))
        {
            _logger.LogInformation("No signing request tracking log file found for {Date}, starting fresh.", date);
            return;
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);
            _currentDay =
                JsonSerializer.Deserialize<SigningRequestTrackingLogFile>(File.ReadAllText(fileName), JsonOptions)!;
            _logger.LogInformation("Loaded signing request tracking log file {FileName}", fileName);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Failed to load signing request tracking log file {FileName}", fileName);
        }
    }


    public async Task<IList<SigningRequestTrackingLogFile>> LoadAllTrackingFiles(CancellationToken cancellationToken)
    {
        try
        {
            var result = new List<SigningRequestTrackingLogFile>();
            var files = Directory.EnumerateFiles("audit", "*.json");
            foreach (var file in files)
            {
                try
                {
                    var text = await File.ReadAllTextAsync(file, cancellationToken);
                    var logFile = JsonSerializer.Deserialize<SigningRequestTrackingLogFile>(text, JsonOptions);
                    if (logFile != null)
                    {
                        result.Add(logFile);
                    }
                }
                catch (Exception e)
                {
                    _logger.LogError(e, "Failed to load signing request tracking log file {FileName}", file);
                }
            }

            result.Sort((a, b) => a.Date.CompareTo(b.Date));
            return result;
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Failed to load all tracking files");
            return [];
        }
    }

    public void Dispose()
    {
        StopBackgroundFlushWorker();
    }

    private void StopBackgroundFlushWorker()
    {
        _backgroundWorkerCancellation.Cancel();
        _backgroundWorker?.Wait();
    }

    private string GetFileName(DateTime date)
    {
        return Path.Combine("audit", $"signing-requests-{date:yyyy-MM-dd}.json");
    }

    public async Task TrackRequestAsync(
        string userInfo,
        SignFileResponseStatus status, int numberOfSignatures
    )
    {
        var currentDay = await GetCurrentDay(true, CancellationToken.None);
        currentDay.TrackRequest(userInfo, status, numberOfSignatures);
    }
}
