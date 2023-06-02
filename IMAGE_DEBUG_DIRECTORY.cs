using System.Runtime.InteropServices;

namespace PE2PDBUrl
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_DEBUG_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Type;
        public uint SizeOfData;
        public uint AddressOfRawData;
        public uint PointerToRawData;
    }
}
