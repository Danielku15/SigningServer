using System.Collections.Generic;
using System.Linq;
using SigningServer.Contracts;

namespace SigningServer.Server.SigningTool
{
    public class EnumerableSigningToolProvider : ISigningToolProvider
    {
        private readonly IEnumerable<ISigningTool> _signingTools;

        public EnumerableSigningToolProvider(IEnumerable<ISigningTool> signingTools)
        {
            _signingTools = signingTools;
        }

        public ISigningTool GetSigningTool(string fileName)
        {
            return _signingTools.FirstOrDefault(signingTool => signingTool.IsFileSupported(fileName));
        }

        public string[] GetSupportedFileExtensions()
        {
            return _signingTools.SelectMany(c => c.GetSupportedFileExtensions()).ToArray();
        }
    }
}