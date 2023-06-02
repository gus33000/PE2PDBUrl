using System.Runtime.InteropServices;

namespace PE2PDBUrl
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("PE2PDBUrl <PE File>");
                return;
            }

            string file = args[0];
            if (!File.Exists(file))
            {
                Console.WriteLine($"{file} does not exist");
                return;
            }

            PEDebugInformation peDebugInformation = PEDebugInformation.GetDebugURLs(file);

            if (string.IsNullOrEmpty(peDebugInformation.PEUrl) || string.IsNullOrEmpty(peDebugInformation.PDBUrl))
            {
                Console.WriteLine($"{file} cannot be parsed correctly to retrieve debug information");
                return;
            }

            Console.WriteLine($"PE File: {file}");
            Console.WriteLine($"PE Url: {peDebugInformation.PEUrl}");
            Console.WriteLine($"PDB Url: {peDebugInformation.PDBUrl}");
        }
    }
}