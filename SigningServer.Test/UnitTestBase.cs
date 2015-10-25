using System.Reflection;
using NUnit.Framework;

namespace SigningServer.Test
{
    public class UnitTestBase
    {
        [SetUp]
        public void SetupBase()
        {
            var deploymentItems = GetType().GetMethod(TestContext.CurrentContext.Test.Name).GetCustomAttributes<DeploymentItemAttribute>();
            foreach (var item in deploymentItems)
            {
                item.Deploy();
            }
        }
    }
}
