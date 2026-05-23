namespace PcapViewer.Core.Models;

/// <summary>A file/object carved out of the capture by tshark's --export-objects.</summary>
public sealed class ExtractedObject
{
    public string Name { get; init; } = "";
    public long SizeBytes { get; init; }

    /// <summary>Absolute path where the object was written on disk.</summary>
    public string SavedPath { get; init; } = "";
}
