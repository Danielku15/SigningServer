using System.Collections.Generic;
using SigningServer.Core;

namespace SigningServer.Server.SigningTool;

public interface ISigningToolProvider
{
    ISigningTool GetSigningTool(string fileName);
    IList<ISigningTool> AllTools { get; }
}
