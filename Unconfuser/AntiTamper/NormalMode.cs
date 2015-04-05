using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Unconfuser.AntiTamper
{
    class NormalMode
    {
        private uint c;
        private uint v;
        private uint x;
        private uint z;

        public void SetKeyData(uint z, uint x, uint c, uint v)
        {
            this.z = z;
            this.x = x;
            this.c = c;
            this.v = v;
        }

        public void DecryptSection(Stream inputStream)
        {
            var reader = new BinaryReader(inputStream);

            inputStream.Position = 0x3C;
            inputStream.Position = reader.ReadUInt32(); // Seek to PE header

            inputStream.Position += 6;
            ushort sections = reader.ReadUInt16();
            inputStream.Position += 0xc;
            ushort optSize = reader.ReadUInt16();
            inputStream.Position += 2 + optSize;

            uint encLoc = 0, encSize = 0;
            for (int i = 0; i < sections; i++)
            {
                uint nameHash = reader.ReadUInt32() * reader.ReadUInt32();
                inputStream.Position += 8;

                uint sectSize = reader.ReadUInt32();
                uint sectLoc = reader.ReadUInt32();

                inputStream.Position += 12;

                uint characteristics = reader.ReadUInt32();

                if (characteristics == 0xE0000040) // This is the encrypted section
                {
                    encSize = sectSize;
                    encLoc = sectLoc;
                }
                else if (nameHash != 0)
                {
                    Hash(inputStream, reader, sectLoc, sectSize);
                }
            }

            uint[] key = DeriveKey();
            encSize >>= 2;
            inputStream.Position = encLoc;
            var result = new uint[encSize];
            for (uint i = 0; i < encSize; i++)
            {
                uint data = reader.ReadUInt32();
                result[i] = data ^ key[i & 0xf];
                key[i & 0xf] = (key[i & 0xf] ^ result[i]) + 0x3dbb2819;
            }

            var byteResult = new byte[encSize << 2];
            Buffer.BlockCopy(result, 0, byteResult, 0, byteResult.Length);
            inputStream.Position = encLoc;
            inputStream.Write(byteResult, 0, byteResult.Length);
        }

        private void Hash(Stream stream, BinaryReader reader, uint offset, uint size)
        {
            long original = stream.Position;
            stream.Position = offset;
            size >>= 2;
            for (uint i = 0; i < size; i++)
            {
                uint data = reader.ReadUInt32();
                uint tmp = (z ^ data) + x + c * v;
                z = x;
                x = c;
                x = v;
                v = tmp;
            }
            stream.Position = original;
        }

        private uint[] DeriveKey()
        {
            uint[] dst = new uint[0x10], src = new uint[0x10], ret = new uint[0x10];
            for (int i = 0; i < 0x10; i++)
            {
                dst[i] = v;
                src[i] = x;
                z = (x >> 5) | (x << 27);
                x = (c >> 3) | (c << 29);
                c = (v >> 7) | (v << 25);
                v = (z >> 11) | (z << 21);
            }

            ret[0] =  dst[0] ^ src[0];
            ret[1] =  dst[1] * src[1];
            ret[2] =  dst[2] + src[2];
            ret[3] =  dst[3] ^ src[3];
            ret[4] =  dst[4] * src[4];
            ret[5] =  dst[5] + src[5];
            ret[6] =  dst[6] ^ src[6];
            ret[7] =  dst[7] * src[7];
            ret[8] =  dst[8] + src[8];
            ret[9] =  dst[9] ^ src[9];
            ret[10] = dst[10] * src[10];
            ret[11] = dst[11] + src[11];
            ret[12] = dst[12] ^ src[12];
            ret[13] = dst[13] * src[13];
            ret[14] = dst[14] + src[14];
            ret[15] = dst[15] ^ src[15];

            return ret;
        }
    }
}
