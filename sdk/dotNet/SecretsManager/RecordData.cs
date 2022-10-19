using System.Diagnostics.CodeAnalysis;

namespace SecretsManager
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class KeeperRecordData
    {
        public string title { get; set; }
        public string type { get; set; }
        public KeeperRecordField[] fields { get; set; }
        public KeeperRecordField[] custom { get; set; }
        public string notes { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class KeeperRecordField
    {
        public string type { get; set; }
        public string label { get; set; }
        public object[] value { get; set; }
        public bool required { get; set; }
        public bool privacyScreen { get; set; }
        public bool enforceGeneration { get; set; }
        public object complexity { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class KeeperFileData
    {
        public string title { get; set; }
        public string name { get; set; }
        public string type { get; set; }
        public long size { get; set; }
        public long lastModified { get; set; }
    }
}