using System;

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
                            return;
                        case "-remove":
                            Console.WriteLine("Removing Windows Service");
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
