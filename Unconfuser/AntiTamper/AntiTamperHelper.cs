using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;

using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using dnlib.DotNet.MD;

namespace Unconfuser.AntiTamper
{
    public static class AntiTamperHelper
    {
        class AntiTamperKeys
        {
            public uint c;
            public uint v;
            public uint x;
            public uint z;
        }

        private static MethodDef GetInitializeMethod(ModuleDefMD module)
        {
            var globalType = module.GlobalType;
            foreach (var method in globalType.Methods)
            {
                // TOOD: Better detection
                if (method.Body != null && method.Body.Instructions.Count > 5 && method.Body.Instructions[5].OpCode == OpCodes.Callvirt)
                {
                    return method;
                }
            }

            throw new Exception("Could not find initialize method");
        }

        private static uint GetKeyFromInstruction(Instruction inst)
        {
            if (!inst.IsLdcI4())
            {
                throw new Exception("Invalid instruction");
            }

            return (uint)(int)inst.Operand;
        }

        private static AntiTamperKeys GetKeys(ModuleDefMD module)
        {
            AntiTamperKeys keys = new AntiTamperKeys();

            // Find the AntiTamperNormal.Initialize method
            var method = GetInitializeMethod(module);

            // Get the keys out of the instructions
            // TODO: Do this dynamically rather than relying on instruction offsets

            // 55, 57, 59, 61
            keys.z = GetKeyFromInstruction(method.Body.Instructions[55]);
            keys.x = GetKeyFromInstruction(method.Body.Instructions[57]);
            keys.c = GetKeyFromInstruction(method.Body.Instructions[59]);
            keys.v = GetKeyFromInstruction(method.Body.Instructions[61]);

            return keys;
        }

        public static ModuleDefMD GetDecryptedModule(ModuleDefMD module)
        {
            var keys = GetKeys(module);

            var processor = new NormalMode();
            processor.SetKeyData(keys.z, keys.x, keys.c, keys.v);

            // Read the whole module
            var moduleStream = module.MetaData.PEImage.CreateFullStream();
            var moduleData = moduleStream.ReadBytes((int)moduleStream.Length);

            var memStream = new MemoryStream(moduleData);

            processor.DecryptSection(memStream);

            return ModuleDefMD.Load(memStream);
        }
    }
}

