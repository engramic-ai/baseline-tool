using System.Text.Json.Serialization;

namespace Engramic.Baseline.Model;

/// <summary>
/// The hardware block of status.json, for fleet reporting; the full inventory goes in findings.json.
/// </summary>
/// <remarks>
/// Filled once the hardware inventory is ported. Until then status.json holds null here, as the
/// PowerShell tool writes when it has no inventory.
/// </remarks>
public sealed record StatusHardware
{
    /// <summary>Gets the maker of the device.</summary>
    [JsonPropertyName("manufacturer")]
    public required string Manufacturer { get; init; }

    /// <summary>Gets the model of the device.</summary>
    [JsonPropertyName("model")]
    public required string Model { get; init; }

    /// <summary>Gets the system SKU.</summary>
    [JsonPropertyName("systemSku")]
    public required string SystemSku { get; init; }

    /// <summary>Gets the serial number.</summary>
    [JsonPropertyName("serialNumber")]
    public required string SerialNumber { get; init; }

    /// <summary>Gets whether the device is a virtual machine.</summary>
    [JsonPropertyName("isVirtualMachine")]
    public required bool IsVirtualMachine { get; init; }

    /// <summary>Gets the BIOS or UEFI firmware version.</summary>
    [JsonPropertyName("firmwareVersion")]
    public required string FirmwareVersion { get; init; }

    /// <summary>Gets the release date of the firmware, as the inventory reports it.</summary>
    [JsonPropertyName("firmwareDate")]
    public required string FirmwareDate { get; init; }

    /// <summary>Gets the firmware type, such as UEFI.</summary>
    [JsonPropertyName("firmwareType")]
    public required string FirmwareType { get; init; }

    /// <summary>Gets the maker of the TPM.</summary>
    [JsonPropertyName("tpmManufacturer")]
    public required string TpmManufacturer { get; init; }

    /// <summary>Gets the TPM firmware version.</summary>
    [JsonPropertyName("tpmFirmware")]
    public required string TpmFirmware { get; init; }

    /// <summary>Gets the TPM specification version.</summary>
    [JsonPropertyName("tpmSpec")]
    public required string TpmSpec { get; init; }

    /// <summary>Gets the name of the first processor.</summary>
    [JsonPropertyName("cpu")]
    public required string Cpu { get; init; }

    /// <summary>Gets the disks.</summary>
    [JsonPropertyName("disks")]
    public required IReadOnlyList<StatusDisk> Disks { get; init; }
}
