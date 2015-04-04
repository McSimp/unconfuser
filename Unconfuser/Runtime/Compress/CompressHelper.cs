using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using dnlib.DotNet.MD;

namespace Unconfuser.Runtime.Compress
{
    public static class CompressHelper
    {
        static List<Instruction> GetCryptInstructions(MethodDef decryptMethod)
        {
            var cryptInstructions = new List<Instruction>();
            var enumerator = decryptMethod.Body.Instructions.GetEnumerator();

            var inCrypt = false;
            while (enumerator.MoveNext())
            {
                Instruction inst = enumerator.Current;

                // Continue moving through instructions until we're in the crypt section
                if (!inCrypt)
                {
                    if (inst.OpCode == OpCodes.Blt_S)
                    {
                        inCrypt = true;
                    }
                    continue;
                }

                // We're now in the crypt section
                cryptInstructions.Add(inst);

                // If we've reached a call, we've got all the crypt instructions and need to remove the last 4 instructions
                if (inst.OpCode == OpCodes.Call)
                {
                    cryptInstructions.RemoveRange(cryptInstructions.Count - 4, 4);
                    break;
                }
            }

            return cryptInstructions;
        }

        static void EnsureInstruction(ref List<Instruction>.Enumerator enumerator, OpCode opCode)
        {
            if (!enumerator.MoveNext())
            {
                throw new Exception("Invalid instruction");
            }

            var inst = enumerator.Current;
            if (opCode == OpCodes.Ldc_I4 && inst.IsLdcI4())
            {
                return;
            }

            if (opCode == OpCodes.Ldloc && inst.IsLdloc())
            {
                return;
            }

            if (inst.OpCode != opCode)
            {
                throw new Exception("Unexpected instruction");
            }
        }

        static OpCode GetCryptOperation(ref List<Instruction>.Enumerator enumerator)
        {
            if (!enumerator.MoveNext())
            {
                throw new Exception("Invalid instruction");
            }

            var opCode = enumerator.Current.OpCode;
            if (opCode != OpCodes.Xor && opCode != OpCodes.Mul && opCode != OpCodes.Add)
            {
                throw new Exception("Invalid opcode");
            }

            return opCode;
        }

        static DecryptConfiguration ParseCryptInstructions(List<Instruction> cryptInstructions)
        {
            DecryptConfiguration config = new DecryptConfiguration();
            var ie = cryptInstructions.GetEnumerator();

            for (int i = 0; i < 0x10; i++)
            {
                EnsureInstruction(ref ie, OpCodes.Ldloc);
                EnsureInstruction(ref ie, OpCodes.Ldc_I4);
                EnsureInstruction(ref ie, OpCodes.Ldloc);
                EnsureInstruction(ref ie, OpCodes.Ldc_I4);
                EnsureInstruction(ref ie, OpCodes.Ldelem_U4);
                EnsureInstruction(ref ie, OpCodes.Ldloc);
                EnsureInstruction(ref ie, OpCodes.Ldc_I4);
                EnsureInstruction(ref ie, OpCodes.Ldelem_U4);

                config.InitialBlockOps[i] = GetCryptOperation(ref ie);

                EnsureInstruction(ref ie, OpCodes.Ldc_I4);
                var key = (int)ie.Current.Operand;
                var op = GetCryptOperation(ref ie);

                if (op == OpCodes.Add)
                {
                    config.k1 = key;
                }
                else if (op == OpCodes.Xor)
                {
                    config.k2 = key;
                }
                else if (op == OpCodes.Mul)
                {
                    config.k3 = key;
                }

                config.FinalBlockOps[i] = op;

                EnsureInstruction(ref ie, OpCodes.Stelem_I4);
            }

            return config;
        }

        static DecryptConfiguration GetDecryptConfiguration(MethodDef decryptMethod)
        {
            var cryptInstructions = GetCryptInstructions(decryptMethod);
            return ParseCryptInstructions(cryptInstructions);
        }

        static uint PerformDecryptOp(OpCode op, uint a, uint b)
        {
            if (op == OpCodes.Xor)
            {
                return a ^ b;
            }

            if (op == OpCodes.Mul)
            {
                return a * b;
            }

            if (op == OpCodes.Add)
            {
                return a + b;
            }

            throw new Exception("Invalid operation");
        }

        static uint PerformKeyedDecryptOp(OpCode op, DecryptConfiguration config, uint val)
        {
            if (op == OpCodes.Add)
            {
                return val + (uint)config.k1;
            }

            if (op == OpCodes.Xor)
            {
                return val ^ (uint)config.k2;
            }

            if (op == OpCodes.Mul)
            {
                return val * (uint)config.k3;
            }

            throw new Exception("Invalid operation");
        }

        static byte[] Decrypt(DecryptConfiguration config, uint[] data, uint seed)
        {
            var w = new uint[0x10];
            var k = new uint[0x10];
            ulong s = seed;
            for (int i = 0; i < 0x10; i++)
            {
                s = (s * s) % 0x143fc089;
                k[i] = (uint)s;
                w[i] = (uint)((s * s) % 0x444d56fb);
            }

            for (int i = 0; i < 0x10; i++)
            {
                var temp = PerformDecryptOp(config.InitialBlockOps[i], w[i], k[i]);
                w[i] = PerformKeyedDecryptOp(config.FinalBlockOps[i], config, temp);
            }

            Array.Clear(k, 0, 0x10);

            var b = new byte[data.Length << 2];
            uint h = 0;
            for (int i = 0; i < data.Length; i++)
            {
                uint d = data[i] ^ w[i & 0xf];
                w[i & 0xf] = (w[i & 0xf] ^ d) + 0x3ddb2819;
                b[h + 0] = (byte)(d >> 0);
                b[h + 1] = (byte)(d >> 8);
                b[h + 2] = (byte)(d >> 16);
                b[h + 3] = (byte)(d >> 24);
                h += 4;
            }
            Array.Clear(w, 0, 0x10);
            byte[] j = Lzma.Decompress(b);
            Array.Clear(b, 0, b.Length);

            var z = (uint)(s % 0x8a5cb7);
            for (int i = 0; i < j.Length; i++)
            {
                j[i] ^= (byte)s;
                if ((i & 0xff) == 0)
                    s = (s * s) % 0x8a5cb7;
            }

            return j;
        }

        private static uint GetDecryptionSeed(MethodDef mainMethod, MethodDef decryptMethod)
        {
            Instruction prev = null;

            foreach (var inst in mainMethod.Body.Instructions)
            {
                if (inst.OpCode == OpCodes.Call && inst.Operand == decryptMethod)
                {
                    return (uint)(int)prev.Operand;
                }

                prev = inst;
            }

            throw new Exception("Could not find seed");
        }

        public static byte[] DecompressModule(ModuleDefMD compressedModule)
        {
            // Get required methods
            var globalType = compressedModule.GlobalType;
            var decryptMethod = globalType.FindMethod("Decrypt");
            var mainMethod = globalType.FindMethod("Main");

            // Get Decryption config 
            // ASSUME NORMAL DERIVER - TODO: Determine which deriver used
            var config = GetDecryptConfiguration(decryptMethod);

            // Get encrypted data as a uint array
            var data = compressedModule.GlobalType.FindField("DataField").InitialValue;
            uint[] uintData = new uint[data.Length / 4];

            for (int i = 0; i < data.Length; i += 4)
            {
                uintData[i / 4] = BitConverter.ToUInt32(data, i);
            }

            // Get decryption seed
            uint seed = GetDecryptionSeed(mainMethod, decryptMethod);

            // Get decrypted data
            var decryptedData = Decrypt(config, uintData, seed);

            return decryptedData;
        }
    }
}
