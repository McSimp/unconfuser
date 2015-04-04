using dnlib.DotNet.Emit;

namespace Unconfuser.Runtime.Compress
{
    internal class DecryptConfiguration
    {
        public OpCode[] InitialBlockOps = new OpCode[0x10];
        public OpCode[] FinalBlockOps = new OpCode[0x10];
        public int k1;
        public int k2;
        public int k3;
    }
}
