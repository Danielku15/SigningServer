using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace SigningServer.Test;

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class | AttributeTargets.Struct, AllowMultiple = true,
    Inherited = false)]
public class DeploymentItemAttribute : Attribute
{
    private readonly string _path;
    private readonly string? _outputDirectory;

    /// <summary>
    /// NUnit replacement for Microsoft.VisualStudio.TestTools.UnitTesting.DeploymentItemAttribute
    /// Marks an item to be relevant for a unit-test and copies it to deployment-directory for this unit-test.
    /// </summary>
    /// <param name="path">The relative or absolute path to the file or directory to deploy. The path is relative to the build output directory.</param>
    /// <param name="outputDirectory">The path of the directory to which the items are to be copied. It can be either absolute or relative to the deployment directory.</param>
    public DeploymentItemAttribute(string path, string? outputDirectory = null)
    {
        _path = path;
        _outputDirectory = outputDirectory;
    }

    public void Deploy()
    {
        // Escape input-path to correct back-slashes for Windows
        var filePath = _path.Replace("/", "\\");

        // Look up where we are right now
        var environmentDir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);

        // Get the full path and name of the deployment item
        var itemPath = new Uri(Path.Combine(environmentDir.FullName, filePath)).LocalPath;
        var itemName = Path.GetFileName(itemPath);

        // Get the target-path where to copy the deployment item to
        var binFolderPath = environmentDir.ToString();

        // NUnit uses an obscure ShadowCopyCache directory which can be hard to find, so let's output it so the poor developer can get at it more easily
        Debug.WriteLine("DeploymentItem: Copying " + itemPath + " to " + binFolderPath);

        // Assemble the target path
        string itemPathInBin;
        if (string.IsNullOrEmpty(_outputDirectory))
        {
            itemPathInBin = new Uri(Path.Combine(binFolderPath, itemName)).LocalPath;
        }
        else if (!string.IsNullOrEmpty(Path.GetPathRoot(_outputDirectory)))
        {
            itemPathInBin = new Uri(Path.Combine(_outputDirectory)).LocalPath;
        }
        else
        {
            itemPathInBin = new Uri(Path.Combine(binFolderPath, _outputDirectory)).LocalPath;
        }

        // Decide whether it's a file or a folder
        if (File.Exists(itemPath)) // It's a file
        {
            // Assemble the parent folder path (because the item might be in multiple sub-folders.
            var parentFolderPathInBin = new DirectoryInfo(itemPathInBin).Parent!.FullName;

            // If the target directory does not exist, create it
            if (!Directory.Exists(parentFolderPathInBin))
            {
                Directory.CreateDirectory(parentFolderPathInBin);
            }

            // copy source-file to the destination
            File.Copy(itemPath, itemPathInBin, true);

            // We must allow the destination file to be deletable
            var fileAttributes = File.GetAttributes(itemPathInBin);
            if ((fileAttributes & FileAttributes.ReadOnly) != 0)
            {
                File.SetAttributes(itemPathInBin, fileAttributes & ~FileAttributes.ReadOnly);
            }
        }
        else if (Directory.Exists(itemPath)) // It's a folder
        {
            // If it already exists, remove it
            if (Directory.Exists(itemPathInBin))
            {
                Directory.Delete(itemPathInBin, true);
            }

            // Create target directory
            Directory.CreateDirectory(itemPathInBin);

            // Now Create all of the sub-directories
            foreach (var dirPath in Directory.GetDirectories(itemPath, "*", SearchOption.AllDirectories))
            {
                for (var i = 0; i < 5; i++)
                {
                    try
                    {
                        Directory.CreateDirectory(dirPath.Replace(itemPath, itemPathInBin));
                        break;
                    }
                    catch (UnauthorizedAccessException)
                    {
                        // CreateDirectory sometimes throws for no apparent reason (probably another process interfering)
                        Thread.Sleep(100);
                    }
                }
            }

            //Copy all the files & Replace any files with the same name
            foreach (var sourcePath in Directory.GetFiles(itemPath, "*.*", SearchOption.AllDirectories))
            {
                var destinationPath = sourcePath.Replace(itemPath, itemPathInBin);
                File.Copy(sourcePath, destinationPath, true);

                // We must allow the destination file to be deletable
                var fileAttributes = File.GetAttributes(destinationPath);
                if ((fileAttributes & FileAttributes.ReadOnly) != 0)
                {
                    File.SetAttributes(destinationPath, fileAttributes & ~FileAttributes.ReadOnly);
                }
            }
        }
        else
        {
            Debug.WriteLine("Warning: Deployment item does not exist - \"" + itemPath + "\"");
        }
    }
}
