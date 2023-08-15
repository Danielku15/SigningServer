using System;
using NUnit.Framework.Interfaces;
using NUnit.Framework.Internal;
using NUnit.Framework.Internal.Commands;

namespace SigningServer.Android;

public class TestAttribute : NUnit.Framework.TestAttribute, IWrapTestMethod
{
    public Type Expected { get; set; }

    public TestCommand Wrap(TestCommand command)
    {
        if (Expected != null)
        {
            return new ExpectedExceptionCommand(command, Expected);
        }
        else
        {
            return command;
        }
    }
    
    private class ExpectedExceptionCommand : DelegatingTestCommand
    {
        private readonly Type _expectedType;

        public ExpectedExceptionCommand(TestCommand innerCommand, Type expectedType)
            : base(innerCommand)
        {
            _expectedType = expectedType;
        }

        public override NUnit.Framework.Internal.TestResult Execute(NUnit.Framework.Internal.TestExecutionContext context)
        {
            Type caughtType = null;

            try
            {
                innerCommand.Execute(context);
            }
            catch (Exception ex)
            {
                if (ex is NUnitException)
                {
                    ex = ex.InnerException;
                }
                caughtType = ex!.GetType();
            }

            if (caughtType == _expectedType)
                context.CurrentResult.SetResult(ResultState.Success);
            else if (caughtType != null)
                context.CurrentResult.SetResult(ResultState.Failure,
                    string.Format("Expected {0} but got {1}", _expectedType.Name, caughtType.Name));
            else
                context.CurrentResult.SetResult(ResultState.Failure,
                    string.Format("Expected {0} but no exception was thrown", _expectedType.Name));

            return context.CurrentResult;
        }
    }
}

public class IgnoreAttribute : NUnit.Framework.IgnoreAttribute
{
    public IgnoreAttribute(string reason) : base(reason)
    {
    }
}
