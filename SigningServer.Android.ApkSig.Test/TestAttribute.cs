using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SigningServer.Android
{
    [AttributeUsage(AttributeTargets.Method)]
    public class TestAttribute : TestMethodAttribute
    {
        public Type Expected { get; set; }

        public override TestResult[] Execute(ITestMethod testMethod)
        {
            var result = base.Execute(testMethod);
            if (Expected != null)
            {
                foreach (var testResult in result)
                {
                    if (testResult.Outcome == UnitTestOutcome.Passed)
                    {
                        testResult.Outcome = UnitTestOutcome.Failed;
                        testResult.TestFailureException =
                            new Exception($"Expected exception {Expected.FullName} but none thrown");
                    }
                    else if (testResult.Outcome == UnitTestOutcome.Failed && 
                             testResult.TestFailureException != null &&
                             UnwrapTestException(testResult.TestFailureException).GetType().IsAssignableFrom(Expected))
                    {
                        testResult.Outcome = UnitTestOutcome.Passed;
                        testResult.TestFailureException = null;
                    }
                }
            }
            return result;
        }

        private Exception UnwrapTestException(Exception exception)
        {
            if (exception.GetType().Name == "TestFailedException")
            {
                return exception.InnerException;
            }

            return exception;
        }
    }
}