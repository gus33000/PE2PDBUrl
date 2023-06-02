using System.Runtime.InteropServices;

namespace PE2PDBUrl
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_DEBUG_DIRECTORY_RAW
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public char[] format;
        public Guid guid;
        public uint age;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 255)]
        public char[] name;
    }
}
