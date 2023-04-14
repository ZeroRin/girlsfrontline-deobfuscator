using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using Il2CppInspector;
using Il2CppInspector.PluginAPI;
using Il2CppInspector.PluginAPI.V100;
using Il2CppInspector.Reflection;
using NoisyCowStudios.Bin2Object;
using static Loader.Utils;
using Assembly = System.Reflection.Assembly;

namespace Loader
{
    /// <summary>
    /// Il2CppInspector plugin to enable loading of Girls' Frontline (少女前线).
    ///
    /// <para />
    /// If you want to follow along, offsets in this project refer to <c>arm64-v8a</c> binary <c>libtprt.so</c>
    /// from EN client v<c>2.0702_362</c>, app id <c>com.sunborn.girlsfrontline.en</c>.
    ///
    /// <para />
    /// See <see cref="Utils">Utils.cs</see> for the actual decryption methods.
    /// </summary>
    public class Plugin : IPlugin, ILoadPipeline
    {
        public string Id => "girlsfrontline-deobfuscator";
        public string Name => "Girls' Frontline Deobfuscator";
        public string Author => "neko-gg";
        public string Version => "1.1";
        public string Description => "Enables loading of Girls' Frontline (少女前线)";

        private string PreferredArch { get; set; } = null;

        private readonly PluginOptionBoolean _stcExportEnabledOption = new PluginOptionBoolean
        {
            Name = "stc-export-enabled",
            Description = "Export STC format files",
            Value = true,
            Required = true
        };

        private readonly PluginOptionFilePath _stcFormatPathOption = new PluginOptionFilePath
        {
            Name = "stc-format-path",
            Description = "Output folder for STC format files\n⚠️This directory and all its content will be deleted!",
            IsFolder = true,
            MustExist = false,
            Value = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "girls-frontline", "stc-format"),
            Required = true
        };

        private readonly PluginOptionNumber<uint> _headerKeySeed0Option = new PluginOptionNumber<uint>
        {
            Name = "header-key-seed-0",
            Description = "Metadata header decryption key seed [0]",
            Value = 0xDCD8DB8F, // offset: 0x14DEE9
            Required = true,
            If = () => true,
            Style = PluginOptionNumberStyle.Hex
        };

        private readonly PluginOptionNumber<uint> _headerKeySeed1Option = new PluginOptionNumber<uint>
        {
            Name = "header-key-seed-1",
            Description = "Metadata header decryption key seed [1]",
            Value = 0x8EDCDF8C, // offset: 0x14DEED
            Required = true,
            If = () => true,
            Style = PluginOptionNumberStyle.Hex
        };

        private readonly PluginOptionNumber<uint> _headerKeySeed2Option = new PluginOptionNumber<uint>
        {
            Name = "header-key-seed-2",
            Description = "Metadata header decryption key seed [2]",
            Value = 0x8BD8DB8F, // offset: 0x14DEF1
            Required = true,
            If = () => true,
            Style = PluginOptionNumberStyle.Hex
        };

        private readonly PluginOptionNumber<uint> _headerKeySeed3Option = new PluginOptionNumber<uint>
        {
            Name = "header-key-seed-3",
            Description = "Metadata header decryption key seed [3]",
            Value = 0x8A8A8E89, // offset: 0x14DEF5
            Required = true,
            If = () => true,
            Style = PluginOptionNumberStyle.Hex
        };

        private readonly PluginOptionNumber<byte> _headerLastPassKeySeedOption = new PluginOptionNumber<byte>
        {
            Name = "header-last-pass-key-seed",
            Description = "Metadata header last pass key seed",
            Value = 0x02, // offset: 0xD33E4 - 0xD341C
            Required = true,
            If = () => true,
            Style = PluginOptionNumberStyle.Hex
        };

        private readonly PluginOptionNumber<byte> _headerLastBytesKeyOption = new PluginOptionNumber<byte>
        {
            Name = "header-last-bytes-key",
            Description = "Metadata header last bytes decryption key",
            Value = 0xAF, // offset: 0xC5BD4
            Required = true,
            If = () => true,
            Style = PluginOptionNumberStyle.Hex
        };

        private readonly PluginOptionNumber<byte> _bodyKeySeedOption = new PluginOptionNumber<byte>
        {
            Name = "body-key-seed",
            Description = "Metadata body decryption key seed",
            Value = 0xBF, // offset: 0x1CF20
            Required = true,
            If = () => true,
            Style = PluginOptionNumberStyle.Hex
        };

        private readonly PluginOptionNumber<ushort> _binaryXorStripeSizeOption = new PluginOptionNumber<ushort>
        {
            Name = "binary-xor-stripe-size",
            Description = "IL2CPP binary image XOR stripe size",
            Value = 0x1000, // no offsets here, I eyeballed it
            Required = true,
            If = () => true,
            Style = PluginOptionNumberStyle.Hex
        };

        public List<IPluginOption> Options => new List<IPluginOption>
        {
            _stcExportEnabledOption,
            _stcFormatPathOption,
            _headerKeySeed0Option,
            _headerKeySeed1Option,
            _headerKeySeed2Option,
            _headerKeySeed3Option,
            _headerLastPassKeySeedOption,
            _headerLastBytesKeyOption,
            _bodyKeySeedOption,
            _binaryXorStripeSizeOption
        };

        public Plugin()
        {
            _stcFormatPathOption.If = () => _stcExportEnabledOption.Value;
        }

        public void PreProcessMetadata(BinaryObjectStream stream, PluginPreProcessMetadataEventInfo info)
        {
            PluginServices.For(this).StatusUpdate("Decrypting metadata");
        }

        public void PostProcessImage<T>(FileFormatStream<T> stream, PluginPostProcessImageEventInfo info) where T : FileFormatStream<T>
        {
            if (!(stream is ElfReader32 || stream is ElfReader64))
            {
                Debug.WriteLine($"stream is neither ElfReader32 nor ElfReader64, but {stream.GetType()}; skipping");
                return;
            }

            if (String.IsNullOrEmpty(PreferredArch) || stream.Arch == "ARM64") PreferredArch = stream.Arch;

            PluginServices.For(this).StatusUpdate($"Decrypting {stream.Arch} IL2CPP binary image");
            Dictionary<string, Section> sections = stream.GetSections().GroupBy(s => s.Name).ToDictionary(s => s.Key, s => s.First());

            if (!sections.ContainsKey(".rodata") || !sections.ContainsKey(".text"))
            {
                Debug.WriteLine($"no .rodata or .text section found in {stream.Arch} IL2CPP binary image");
                return;
            }

            // .rodata and .text sections of IL2CPP binary are XOR-encrypted in stripes with a single-byte key;
            // we use a very crude method to determine which one: assume the most common byte in the first stripes
            // of .rodata is 0x00; this is usually the case, representing ~50% of all bytes.
            Section roDataSection = sections[".rodata"];
            Section textSection = sections[".text"];

            // even though only odd stripes are encrypted, we also try and decrypt even ones because
            // Il2CppInspector XOR-Decryptor plugin likes to sometimes assume that the assembly it's not actually
            // striped, so we reverse the "encryption" if that's the case;
            // thanks to XOR properties, if there's nothing to decrypt, the most common byte would be 0x00
            // and we'd basically end up doing nothing (A ^ 0 == A, for every A), so no extra checks are performed
            int stripeSize = _binaryXorStripeSizeOption.Value;
            int firstBlockLength = GetFirstBlockLength(roDataSection, stripeSize);
            byte oddMostCommonByte = MostCommonByte(stream, roDataSection.ImageStart, 0, firstBlockLength);
            byte evenMostCommonByte = MostCommonByte(stream, roDataSection.ImageStart, firstBlockLength, stripeSize);

            XorSection(stream, textSection, stripeSize, firstBlockLength, oddMostCommonByte, evenMostCommonByte);
            XorSection(stream, roDataSection, stripeSize, firstBlockLength, oddMostCommonByte, evenMostCommonByte);

            info.IsStreamModified = true;
        }

        public void PostProcessTypeModel(TypeModel model, PluginPostProcessTypeModelEventInfo data)
        {
            if (!_stcExportEnabledOption.Value)
            {
                Debug.WriteLine("STC format files export is disabled; skipping");
                return;
            }

            if (PreferredArch != model.Package.BinaryImage.Arch)
            {
                Debug.WriteLine($"skipping STC format files export for arch {model.Package.BinaryImage.Arch}");
                return;
            }

            PluginServices.For(this).StatusUpdate("Exporting STC format files");

            if (Directory.Exists(_stcFormatPathOption.Value))
            {
                Debug.WriteLine($"recursively deleting directory ${_stcFormatPathOption.Value}");
                Directory.Delete(_stcFormatPathOption.Value, true);
            }

            Dictionary<int, StcFormat> stcFormatDictionary = model.TypesByFullName["Cmd.CmdDef"]
                                                                  .DeclaredFields
                                                                  .Where(field => field.FieldType.IsEnum)
                                                                  .ToDictionary(field => (int) field.DefaultValue, field => GetStcFormat(model, field));


            ExportGflDataMinerStcFormatFiles(stcFormatDictionary);
            ExportGfDecompressStcFormatFiles(stcFormatDictionary);
        }

        private static byte MostCommonByte(IFileFormatStream stream, long imageStart, long offset, int count)
        {
            byte[] bytes = stream.ReadBytes(imageStart + offset, count);
            KeyValuePair<byte, int> mostCommonByteWithCount = MostCommonByteWithCount(bytes);
            byte mostCommonByte = mostCommonByteWithCount.Key;
            int mostCommonByteCount = mostCommonByteWithCount.Value;

            Debug.WriteLine($"[{stream.Arch}] most common byte in {(offset == 0 ? "first" : "second")} stripe of .rodata is 0x{mostCommonByte:X2} with {mostCommonByteCount} occurrences in {bytes.Length} bytes ({Math.Round((double) mostCommonByteCount / bytes.Length * 100d)}%)");
            return mostCommonByte;
        }

        private static void XorSection(BinaryObjectStream stream, Section section, int stripeSize, int firstBlockLength, byte oddXorValue, byte evenXorValue)
        {
            long start = section.ImageStart;
            int length = section.ImageLength;

            XorStripe(stream, start, firstBlockLength, oddXorValue);

            bool oddStripe = false;
            for (long position = start + firstBlockLength; position < start + length; position += stripeSize)
            {
                int size = (int) Math.Min(stripeSize, start + length - position);
                XorStripe(stream, position, size, oddStripe ? oddXorValue : evenXorValue);
                oddStripe = !oddStripe;
            }
        }

        private static void XorStripe(BinaryObjectStream stream, long offset, int length, byte xorKey)
        {
            byte[] bytes = stream.ReadBytes(offset, length);
            bytes = XorBytes(bytes, xorKey);
            stream.Write(offset, bytes);
        }

        private static int GetFirstBlockLength(Section section, int stripeSize)
        {
            long start = (int) section.ImageStart;
            long firstBlockLength = stripeSize;
            long extraCount = start % stripeSize;
            if (extraCount != 0)
                firstBlockLength += stripeSize - extraCount;
            return (int) firstBlockLength;
        }

        private StcFormat GetStcFormat(TypeModel model, FieldInfo fieldInfo)
        {
            string name = new Regex("^stc(.*)List$").Replace(fieldInfo.Name, "$1").ToLowerInvariant();
            return new StcFormat
            {
                Name = name,
                Fields = model.TypesByFullName[$"Cmd.Stc{name[0].ToString().ToUpperInvariant()}{name.Substring(1)}"]
                              .DeclaredFields
                              .Where(field => field.IsPublic)
                              .Select(field => field.Name)
                              .ToList()
            };
        }

        private void ExportGflDataMinerStcFormatFiles(Dictionary<int, StcFormat> stcFormatDictionary)
        {
            JsonSerializerOptions jsonSerializerOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = true
            };

            foreach (var stcFormatEntry in stcFormatDictionary)
            {
                FileInfo file = new FileInfo(Path.Combine(_stcFormatPathOption.Value, "gfl-data-miner", $"{stcFormatEntry.Key}.json"));
                Debug.Assert(file.Directory != null, "stc file directory cannot be null");
                file.Directory.Create();

                string jsonData = JsonSerializer.Serialize(stcFormatEntry.Value, jsonSerializerOptions);

                // very crude way to pretty print STC format files with 4 spaces instead of 2
                string formattedJsonData = new[] {4, 2}.Select(n => new string(' ', n))
                                                       .Aggregate(jsonData, (acc, s) => new Regex($"^{s}(?! )(.*)", RegexOptions.Multiline).Replace(acc, $"{s}{s}$1"));

                File.WriteAllText(file.FullName, formattedJsonData);
            }
        }

        private void ExportGfDecompressStcFormatFiles(Dictionary<int, StcFormat> stcFormatDictionary)
        {
            foreach (var stcFormatEntry in stcFormatDictionary)
            {
                FileInfo file = new FileInfo(Path.Combine(_stcFormatPathOption.Value, "GFDecompress", $"{stcFormatEntry.Key}.format"));
                Debug.Assert(file.Directory != null, "stc file directory cannot be null");
                file.Directory.Create();

                string formatData = String.Join(Environment.NewLine, stcFormatEntry.Value.Fields);
                File.WriteAllText(file.FullName, formatData);
            }

            string gfDecompressMapping = String.Join($",{Environment.NewLine}", stcFormatDictionary.Select(e => $"{{ \"{e.Key}.stc\", \"{e.Value.Name}\" }}"));
            File.WriteAllText(Path.Combine(_stcFormatPathOption.Value, "GFDecompress", "mapping.txt"), gfDecompressMapping);
        }
    }
}
