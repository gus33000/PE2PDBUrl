using System.Runtime.InteropServices;

namespace PE2PDBUrl
{
    internal class PEDebugInformation
    {
        public static PEDebugInformation GetDebugURLs(string filePath)
        {
            return new PEDebugInformation(filePath);
        }

        private PEDebugInformation(string filePath)
        {
            (_PEUrl, _PDBUrl) = ParsePE(filePath);
        }

        private readonly string _PEUrl = string.Empty;

        public string PEUrl
        {
            get => _PEUrl;
        }

        private readonly string _PDBUrl = string.Empty;

        public string PDBUrl
        {
            get => _PDBUrl;
        }

        /// <summary>
        /// The algorithm below is adapted from Microsoft own PDB Downloader utility from 2016 written by Rajkumar Rangaraj
        /// Notably, aside from being adapted for modern .NET, it also implements the ability to gather PE Download URLs.
        /// </summary>
        /// <param name="filePath">The file path to the PE file to analyze</param>
        /// <returns>A tuple containing the PE download url, and the PDB download url</returns>
        private static (string, string) ParsePE(string filePath)
        {
            using FileStream fileStream = new(filePath, FileMode.Open, FileAccess.Read);

            BinaryReader binaryReader = new(fileStream);
            IMAGE_DOS_HEADER dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(binaryReader);

            // Add 4 bytes to the offset
            _ = fileStream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            uint ntHeadersSignature = binaryReader.ReadUInt32();
            IMAGE_FILE_HEADER fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(binaryReader);
            IMAGE_OPTIONAL_HEADER32 optionalHeader32 = new()
            {
                Debug = new()
            };
            IMAGE_OPTIONAL_HEADER64 optionalHeader64 = new()
            {
                Debug = new()
            };

            bool Is32BitHeader = fileHeader.Machine == 332;
            if (Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(binaryReader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(binaryReader);
            }

            uint offDebug = 0;
            long cbFromHeader = 0;
            int loopExit = 0;

            uint cbDebug = Is32BitHeader ? optionalHeader32.Debug.Size : optionalHeader64.Debug.Size;

            IMAGE_SECTION_HEADER[] imageSectionHeaders;

            IMAGE_DEBUG_DIRECTORY imageDebugDirectory = new();
            IMAGE_DEBUG_DIRECTORY_RAW DebugInfo = new();

            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(binaryReader);

                if ((imageSectionHeaders[headerNo].PointerToRawData != 0) &&
                        (imageSectionHeaders[headerNo].SizeOfRawData != 0) &&
                            (cbFromHeader <
                                imageSectionHeaders[headerNo].PointerToRawData + imageSectionHeaders[headerNo].SizeOfRawData))
                {
                    cbFromHeader =
                        imageSectionHeaders[headerNo].PointerToRawData + imageSectionHeaders[headerNo].SizeOfRawData;
                }

                if (cbDebug != 0)
                {
                    if (Is32BitHeader)
                    {
                        if (imageSectionHeaders[headerNo].VirtualAddress <= optionalHeader32.Debug.VirtualAddress &&
                                ((imageSectionHeaders[headerNo].VirtualAddress + imageSectionHeaders[headerNo].SizeOfRawData) > optionalHeader32.Debug.VirtualAddress))
                        {
                            offDebug = optionalHeader32.Debug.VirtualAddress - imageSectionHeaders[headerNo].VirtualAddress + imageSectionHeaders[headerNo].PointerToRawData;
                        }
                    }
                    else
                    {
                        if (imageSectionHeaders[headerNo].VirtualAddress <= optionalHeader64.Debug.VirtualAddress &&
                            ((imageSectionHeaders[headerNo].VirtualAddress + imageSectionHeaders[headerNo].SizeOfRawData) > optionalHeader64.Debug.VirtualAddress))
                        {
                            offDebug = optionalHeader64.Debug.VirtualAddress - imageSectionHeaders[headerNo].VirtualAddress + imageSectionHeaders[headerNo].PointerToRawData;
                        }
                    }
                }
            }

            _ = fileStream.Seek(offDebug, SeekOrigin.Begin);

            while (cbDebug >= Marshal.SizeOf(typeof(IMAGE_DEBUG_DIRECTORY)))
            {
                if (loopExit == 0)
                {
                    imageDebugDirectory = FromBinaryReader<IMAGE_DEBUG_DIRECTORY>(binaryReader);
                    long seekPosition = fileStream.Position;

                    if (imageDebugDirectory.Type == 0x2)
                    {
                        _ = fileStream.Seek(imageDebugDirectory.PointerToRawData, SeekOrigin.Begin);
                        DebugInfo = FromBinaryReader<IMAGE_DEBUG_DIRECTORY_RAW>(binaryReader);
                        loopExit = 1;

                        // Downloading logic for .NET native images
                        if (new string(DebugInfo.name).Contains(".ni."))
                        {
                            _ = fileStream.Seek(seekPosition, SeekOrigin.Begin);
                            loopExit = 0;
                        }
                    }

                    if ((imageDebugDirectory.PointerToRawData != 0) &&
                            (imageDebugDirectory.SizeOfData != 0) &&
                            (cbFromHeader <
                                imageDebugDirectory.PointerToRawData + imageDebugDirectory.SizeOfData))
                    {
                        cbFromHeader =
                            imageDebugDirectory.PointerToRawData + imageDebugDirectory.SizeOfData;
                    }
                }

                cbDebug -= (uint)Marshal.SizeOf(typeof(IMAGE_DEBUG_DIRECTORY));
            }

            string pdbUrl = string.Empty;
            string peUrl = string.Empty;

            if (loopExit != 0)
            {
                peUrl = GetPEUrl(imageDebugDirectory, Is32BitHeader, optionalHeader32, optionalHeader64, filePath);
                pdbUrl = GetPDBUrl(DebugInfo);
            }

            return (peUrl, pdbUrl);
        }

        private static string GetPDBUrl(IMAGE_DEBUG_DIRECTORY_RAW DebugInfo)
        {
            string pdbName = new(DebugInfo.name);
            pdbName = pdbName.Split('\0')[0];

            string pdbAge = DebugInfo.age.ToString("X");
            Guid debugGUID = DebugInfo.guid;

            if (pdbName.Contains('\\'))
            {
                pdbName = pdbName.Split(new char[] { '\\' })[^1];
            }

            return $"http://msdl.microsoft.com/download/symbols/{pdbName}/{debugGUID.ToString("N").ToUpper()}{pdbAge}/{pdbName}";
        }

        private static string GetPEUrl(IMAGE_DEBUG_DIRECTORY imageDebugDirectory, bool Is32BitHeader, IMAGE_OPTIONAL_HEADER32 optionalHeader32, IMAGE_OPTIONAL_HEADER64 optionalHeader64, string filePath)
        {
            string peTimeStamp = imageDebugDirectory.TimeDateStamp.ToString("X");
            uint cbImageSize = Is32BitHeader ? optionalHeader32.SizeOfImage : optionalHeader64.SizeOfImage;

            string peSize = cbImageSize.ToString("X");
            string fileName = Path.GetFileName(filePath);

            return $"http://msdl.microsoft.com/download/symbols/{fileName}/{peTimeStamp}{peSize}/{fileName}";
        }

        private static T? FromBinaryReader<T>(BinaryReader reader)
        {
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T? theStructure = Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            handle.Free();

            return theStructure;
        }
    }
}
