using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SigningServer.Core;
using SigningServer.Server;

namespace SigningServer.Test;

public class TestingSigningRequestTracker : ISigningRequestTracker
{
    public SigningRequestTrackingLogFile CurrentDay { get; } = new();

    public Task TrackRequestAsync(string userInfo, SignFileResponseStatus status, int numberOfSignatures)
    {
        CurrentDay.TrackRequest(userInfo, status, numberOfSignatures);
        return Task.CompletedTask;
    }

    public Task<IList<SigningRequestTrackingLogFile>> LoadAllTrackingFiles(CancellationToken cancellationToken)
    {
        return Task.FromResult((IList<SigningRequestTrackingLogFile>) [CurrentDay]);
    }
}
