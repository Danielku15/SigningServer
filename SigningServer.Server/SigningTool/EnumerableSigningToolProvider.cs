using System.Collections.Generic;
using System.Linq;
using SigningServer.Core;

namespace SigningServer.Server.SigningTool;

public class EnumerableSigningToolProvider : ISigningToolProvider
{
    public EnumerableSigningToolProvider(IList<ISigningTool> signingTools)
    {
        AllTools = signingTools;
    }
    
    public IList<ISigningTool> AllTools { get; }

    public ISigningTool GetSigningTool(string fileName)
    {
        return AllTools.FirstOrDefault(signingTool => signingTool.IsFileSupported(fileName));
    }
}
