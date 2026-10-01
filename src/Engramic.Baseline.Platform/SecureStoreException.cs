namespace Engramic.Baseline.Platform;

/// <summary>
/// The data folder, or a file in it, cannot be trusted or used safely. The message says why and names
/// the path; nothing was changed to get round it.
/// </summary>
/// <remarks>
/// Most are judgements: the item breaks a rule, and will until an administrator changes it. When
/// <see cref="IsUnavailable"/> is set, nothing was judged: the item could not be opened or read at the
/// time, as when another process holds it open without sharing, locks part of it or holds an oplock on it,
/// or a device fails, so what it holds is not known. When <see cref="IsFolderRefused"/> is set, what was
/// judged and refused is the folder a file was to be read from, not the file.
/// </remarks>
public sealed class SecureStoreException : IOException
{
    /// <summary>Makes the exception with a general message.</summary>
    public SecureStoreException()
        : base("The data folder cannot be trusted or used safely.")
    {
    }

    /// <summary>Makes the exception.</summary>
    /// <param name="message">Why, naming the path.</param>
    public SecureStoreException(string message)
        : base(message)
    {
    }

    /// <summary>Makes the exception from the error that caused it.</summary>
    /// <param name="message">Why, naming the path.</param>
    /// <param name="innerException">The error that caused it.</param>
    public SecureStoreException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Makes the exception, saying whether the item was judged or could not be read at all.</summary>
    /// <param name="message">Why, naming the path.</param>
    /// <param name="isUnavailable">True when the item could not be opened or read at the time, rather than judged.</param>
    /// <param name="innerException">The error that caused it, if any.</param>
    public SecureStoreException(string message, bool isUnavailable, Exception? innerException)
        : base(message, innerException)
    {
        IsUnavailable = isUnavailable;
    }

    /// <summary>
    /// Gets whether the item could not be opened or read at the time, rather than being judged against the rules:
    /// held open or locked by another process, an oplock that was not given up, or a device error. Trying again
    /// later may succeed, and nothing is known about what the item holds.
    /// </summary>
    public bool IsUnavailable { get; }

    /// <summary>
    /// Gets whether what was refused is the folder kept in the data folder that a file was to be read from, rather
    /// than the file: the folder fails the trust rules, or this account may not open it to judge it. Nothing in it
    /// was opened, so whether the file is there is not known. Only a store that changes nothing refuses such a
    /// folder; SecureStore moves it aside instead, and reads nothing from it.
    /// </summary>
    public bool IsFolderRefused { get; init; }
}
