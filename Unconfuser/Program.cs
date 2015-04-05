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
        static void Main(string[] args)
        {
            byte[] data = System.IO.File.ReadAllBytes(@"F:\dev\unconfuser\orig.dll");
            ModuleDefMD compressedModule = ModuleDefMD.Load(data);

            var decompressedModuleData = Runtime.Compress.CompressHelper.DecompressModule(compressedModule);

            var decompressedModule = ModuleDefMD.Load(decompressedModuleData);
            var decryptedModule = AntiTamper.AntiTamperHelper.GetDecryptedModule(decompressedModule);

            var writerOptions = new ModuleWriterOptions(decryptedModule);
            writerOptions.Logger = DummyLogger.ThrowModuleWriterExceptionOnErrorInstance;

            // This defeats the InvalidMetadataProtection (just writing out the module again)
            decryptedModule.Write(@"F:\dev\unconfuser\decomp-dnlib.dll", writerOptions);

            System.IO.File.WriteAllBytes(@"F:\dev\unconfuser\decomp.dll", decompressedModuleData);
        }
    }
}

// F:\dev\bl\TestingDLL\CSharpStuff\bin\Debug\decrypted-clean.dll IS THE GOOD FILE!
