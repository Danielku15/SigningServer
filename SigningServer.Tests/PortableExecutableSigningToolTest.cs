using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using SigningServer.MsSign;

namespace SigningServer.Test;


public class PortableExecutableSigningToolTest : UnitTestBase
{
    [Test]
    public async Task IsFileSigned_Dll_UnsignedFile_ReturnsFalse()
    {
        var signingTool = CreateSignTool();
        File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll")).Should().BeTrue();
        (await signingTool.IsFileSignedAsync(Path.Combine(ExecutionDirectory, "TestFiles/unsigned/unsigned.dll"), CancellationToken.None)).Should().BeFalse();
    }

    private static PortableExecutableSigningTool CreateSignTool()
    {
        return new PortableExecutableSigningTool(AssemblyEvents.LoggerProvider.CreateLogger<PortableExecutableSigningTool>());
    }

    [Test]
    public async Task IsFileSigned_Dll_SignedFile_ReturnsTrue()
    {
        var signingTool = CreateSignTool();
        File.Exists(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll")).Should().BeTrue();
        (await signingTool.IsFileSignedAsync(Path.Combine(ExecutionDirectory, "TestFiles/signed/signed.dll"), CancellationToken.None)).Should().BeTrue();
    }

    [Test]
    [DeploymentItem("TestFiles", "Unsign_Works")]
    public async Task Unsign_Dll_Works()
    {
        var signingTool = CreateSignTool();
        var file = Path.Combine(ExecutionDirectory, "Unsign_Works/signed/signed.dll");
        (await signingTool.IsFileSignedAsync(file, CancellationToken.None)).Should().BeTrue();
        signingTool.UnsignFile(file);
        (await signingTool.IsFileSignedAsync(file, CancellationToken.None)).Should().BeFalse();
    }

    #region Signing Works

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_Exe_Works()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.exe"));
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_Dll_Works()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.dll"));
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_Cab_Works()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.cab"));
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_Msi_Works()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.msi"));
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_Sys_Works()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.sys"));
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_Cat_Works()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.cat"));
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works")]
    public async Task SignFile_Unsigned_Arx_Works()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works/unsigned/unsigned.arx"));
    }

    #endregion

    #region Signing Works (Sha1)

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public async Task SignFile_Unsigned_Exe_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.exe"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.exe"), Sha1Oid);
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public async Task SignFile_Unsigned_Dll_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.dll"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.dll"), Sha1Oid);
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public async Task SignFile_Unsigned_Cab_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cab"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cab"), Sha1Oid);
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public async Task SignFile_Unsigned_Msi_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.msi"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.msi"), Sha1Oid);
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public async Task SignFile_Unsigned_Sys_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.sys"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.sys"), Sha1Oid);
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public async Task SignFile_Unsigned_Cat_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cat"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.cat"), Sha1Oid);
    }

    [Test]
    [DeploymentItem("TestFiles", "SignFile_Works_Sha1")]
    public async Task SignFile_Unsigned_Arx_Works_Sha1()
    {
        var signingTool = CreateSignTool();
        await CanSignAsync(signingTool, Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.arx"), "SHA1");
        EnsureSignature(Path.Combine(ExecutionDirectory, "SignFile_Works_Sha1/unsigned/unsigned.arx"), Sha1Oid);
    }

    #endregion

    #region Resign Fails

    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_Exe_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        await CannotResignAsync(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.exe"));
    }

    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_Dll_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        await CannotResignAsync(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.dll"));
    }

    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_Cab_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        await CannotResignAsync(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.cab"));
    }

    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_Msi_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        await CannotResignAsync(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.msi"));
    }

    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_Sys_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        await CannotResignAsync(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.sys"));
    }

    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_Cat_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        await CannotResignAsync(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.cat"));
    }

    [Test]
    [DeploymentItem("TestFiles", "NoResign_Fails")]
    public async Task SignFile_Signed_Arx_NoResign_Fails()
    {
        var signingTool = CreateSignTool();
        await CannotResignAsync(signingTool, Path.Combine(ExecutionDirectory, "NoResign_Fails/signed/signed.arx"));
    }

    #endregion

    #region Resign Works

    [Test]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_Exe_Resign_Works()
    {
        var signingTool = CreateSignTool();
        await CanResignAsync(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.exe"));
    }

    [Test]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_Dll_Resign_Works()
    {
        var signingTool = CreateSignTool();
        await CanResignAsync(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.dll"));
    }

    [Test]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_Cab_Resign_Works()
    {
        var signingTool = CreateSignTool();
        await CanResignAsync(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.cab"));
    }

    [Test]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_Msi_Resign_Works()
    {
        var signingTool = CreateSignTool();
        await CanResignAsync(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.msi"));
    }

    [Test]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_Sys_Resign_Works()
    {
        var signingTool = CreateSignTool();
        await CanResignAsync(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.sys"));
    }

    [Test]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_Cat_Resign_Works()
    {
        var signingTool = CreateSignTool();
        await CanResignAsync(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.cat"));
    }

    [Test]
    [DeploymentItem("TestFiles", "Resign_Works")]
    public async Task SignFile_Signed_Arx_Resign_Works()
    {
        var signingTool = CreateSignTool();
        await CanResignAsync(signingTool, Path.Combine(ExecutionDirectory, "Resign_Works/signed/signed.arx"));
    }

    #endregion
}
