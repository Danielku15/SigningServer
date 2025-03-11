using System.Security.Cryptography.Xml;
using System.Xml;

namespace SigningServer.ClickOnce.MsBuild;

public class ManifestSignedXml2 : SignedXml
{
   
    public ManifestSignedXml2(XmlDocument document) : base(document)
    {
    }

    public ManifestSignedXml2(XmlElement element) : base(element)
    {
    }

    public override XmlElement? GetIdElement(XmlDocument? document, string idValue)
    {
        var keyInfo = this.KeyInfo;
        return keyInfo.Id != idValue ? null : keyInfo.GetXml();
    }
}
