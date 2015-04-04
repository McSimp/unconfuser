using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Reflection;

using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using dnlib.DotNet.MD;

namespace Unconfuser
{
    class Program
    {
        static void OldMain(string[] args)
        {
            FileStream inFile = new FileStream(@"F:\dev\unconfuser\Unconfuser\TestConsoleApp\bin\Debug\Confused\decrypted - Copy.dll", FileMode.Open);
            var processor = new NormalMode();
            
            /* TestingConsoleApp
            uint num4 = 646240056u;
            uint num5 = 3460355740u;
            uint num6 = 2333790704u;
            uint num7 = 1951729657u;
            */

            uint num4 = 1088956851u;
            uint num5 = 2950016400u;
            uint num6 = 2640295951u;
            uint num7 = 3745138235u;
         
            processor.SetKeyData(num4, num5, num6, num7);
            //uint name = unchecked(2049316173U * 1144013385U); // TestingConsoleApp
            uint name = unchecked(961233005U * 50934639U); // decrypted
            processor.DecryptSection(inFile, name);
        }

        static void Main(string[] args)
        {
            string fileName = @"F:\dev\unconfuser\orig.dll";

            byte[] data = System.IO.File.ReadAllBytes(fileName);
            ModuleDefMD compressedModule = ModuleDefMD.Load(data);

            var decompressedModule = Runtime.Compress.CompressHelper.DecompressModule(compressedModule);

            System.IO.File.WriteAllBytes(@"F:\dev\unconfuser\decomp.dll", decompressedModule);
        }
    }
}

// F:\dev\bl\TestingDLL\CSharpStuff\bin\Debug\decrypted-clean.dll IS THE GOOD FILE!
