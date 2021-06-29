//// Copyright (c) Microsoft Corporation.
//// Licensed under the MIT License.

using System.IO;
using System.Reflection;

namespace System.Management.Automation
{
    /// <summary>
    /// Helper fns.
    /// </summary>
    internal static class Utils
    {
        /// <summary>
        /// Helper fn to check arg for empty or null.
        /// Throws ArgumentNullException on either condition.
        /// </summary>
        ///<param name="arg"> arg to check </param>
        ///<param name="argName"> name of the arg </param>
        ///<returns> Does not return a value.</returns>
        internal static void CheckArgForNullOrEmpty(string arg, string argName)
        {
            if (arg == null)
            {
                throw new ArgumentNullException(argName);
            }
            else if (arg.Length == 0)
            {
                throw new ArgumentException(argName);
            }
        }

        /// <summary>
        /// Helper fn to check arg for null.
        /// Throws ArgumentNullException on either condition.
        /// </summary>
        ///<param name="arg"> arg to check </param>
        ///<param name="argName"> name of the arg </param>
        ///<returns> Does not return a value.</returns>
        internal static void CheckArgForNull(object arg, string argName)
        {
            if (arg == null)
            {
                throw new ArgumentNullException(argName);
            }
        }

        internal static string DefaultPowerShellAppBase => GetApplicationBase(DefaultPowerShellShellID);

        internal static string GetApplicationBase(string shellId)
        {
            // Use the location of SMA.dll as the application base.
            Assembly assembly = typeof(Utils).Assembly;
            return Path.GetDirectoryName(assembly.Location);
        }

        /// <summary>
        /// String representing the Default shellID.
        /// </summary>
        internal const string DefaultPowerShellShellID = "Microsoft.PowerShell";

        internal static bool Succeeded(int hresult)
        {
            return hresult >= 0;
        }
    }
}