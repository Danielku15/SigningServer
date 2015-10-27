using System;
using System.Configuration.Install;
using System.Reflection;

namespace SigningServer.Server
{
    class Program
    {
        public static void Main(string[] args)
        {
            if (Environment.UserInteractive)
            {
                if (args.Length == 1)
                {
                    switch (args[0])
                    {
                        case "-install":
                            Console.WriteLine("Installing Windows Service");
                            ManagedInstallerClass.InstallHelper(new [] { Assembly.GetExecutingAssembly().Location });
                            return;
                        case "-remove":
                            Console.WriteLine("Removing Windows Service");
                            ManagedInstallerClass.InstallHelper(new [] { "/u", Assembly.GetExecutingAssembly().Location });
                            return;
                    }
                }

                var server = new SigningServerService();
                server.ConsoleStart();
                Console.ReadLine();
            }
        }
    }
}
