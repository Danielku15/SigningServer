using System.IO;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SigningServer.MsSign;

namespace SigningServer.Test;

[TestClass]
public class PortableExecutableSigningToolTest : UnitTestBase
{
    [TestMethod]
    public void IsFileSigned_Dll_UnsignedFile_ReturnsFalse()
    {
        var signingTool = CreateSignTool();
        Assert.IsTrue(File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")));
        Assert.IsFalse(signingTool.IsFileSigned(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")));
    }

    private static PortableExecutableSigningTool CreateSignTool()
    {
        return new PortableExecutableSigningTool(AssemblyEvents.LoggerProvider.CreateLogger<PortableExecutableSigningTool>());
    }

    [TestMethod]
    public void IsFileSigned_Dll_SignedFile_ReturnsTrue()
    {
        var signingTool = CreateSignTool();
        Assert.IsTrue(File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")));
        Assert.IsTrue(signingTool.IsFileSigned(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Unsign_Works")]
    public void Unsign_Dll_Works()
    {
        var signingTool = CreateSignTool();
        var file = Path.Combine(ExecutionDirectory, "Unsign_Works/signed/signed.dll");
        Assert.IsTrue(signingTool.IsFileSigned(file));
        signingTool.UnsignFile(file);
        Assert.IsFalse(signingTool.IsFileSigned(file));
    }

    #region Signing Works

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public void SignFile_Unsigned_Exe_Works()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.exe"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public void SignFile_Unsigned_Dll_Works()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.dll"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public void SignFile_Unsigned_Cab_Works()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.cab"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public void SignFile_Unsigned_Msi_Works()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.msi"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public void SignFile_Unsigned_Sys_Works()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.sys"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public void SignFile_Unsigned_Cat_Works()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.cat"));
    }

    #endregion

    #region Signing Works (Sha1)

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public void SignFile_Unsigned_Exe_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.exe"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.exe"), Sha1Oid);
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public void SignFile_Unsigned_Dll_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.dll"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.dll"), Sha1Oid);
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public void SignFile_Unsigned_Cab_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cab"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cab"), Sha1Oid);
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public void SignFile_Unsigned_Msi_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.msi"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.msi"), Sha1Oid);
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public void SignFile_Unsigned_Sys_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.sys"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.sys"), Sha1Oid);
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public void SignFile_Unsigned_Cat_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        CanSign(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cat"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cat"), Sha1Oid);
    }

    #endregion

    #region Resign Fails

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public void SignFile_Signed_Exe_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.exe"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public void SignFile_Signed_Dll_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.dll"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public void SignFile_Signed_Cab_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.cab"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public void SignFile_Signed_Msi_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.msi"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public void SignFile_Signed_Sys_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.sys"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public void SignFile_Signed_Cat_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        CannotResign(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.cat"));
    }

    #endregion

    #region Resign Works

    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public void SignFile_Signed_Exe_Resign_Works()
    {
        var signingTool = CreateSignTool();
        CanResign(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.exe"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public void SignFile_Signed_Dll_Resign_Works()
    {
        var signingTool = CreateSignTool();
        CanResign(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.dll"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public void SignFile_Signed_Cab_Resign_Works()
    {
        var signingTool = CreateSignTool();
        CanResign(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.cab"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public void SignFile_Signed_Msi_Resign_Works()
    {
        var signingTool = CreateSignTool();
        CanResign(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.msi"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public void SignFile_Signed_Sys_Resign_Works()
    {
        var signingTool = CreateSignTool();
        CanResign(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.sys"));
    }

    [TestMethod]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public void SignFile_Signed_Cat_Resign_Works()
    {
        var signingTool = CreateSignTool();
        CanResign(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.cat"));
    }

    #endregion
}
