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

        /// <inheritdoc />
        public string[] SupportedFileExtensions => _signingTools.SelectMany(c => c.SupportedFileExtensions).ToArray();
        public string[] SupportedHashAlgorithms => _signingTools.SelectMany(c => c.SupportedHashAlgorithms).Distinct().ToArray();
    }
}