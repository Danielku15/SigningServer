using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SigningServer.Test
{
    public class TestMethodAttribute : Microsoft.VisualStudio.TestTools.UnitTesting.TestMethodAttribute
    {
        public override TestResult[] Execute(ITestMethod testMethod)
        {
            var deploymentItems = testMethod.GetAttributes<DeploymentItemAttribute>(false);
            foreach (var item in deploymentItems)
            {
                item.Deploy();
            }
            return base.Execute(testMethod);
        }

    }
}
