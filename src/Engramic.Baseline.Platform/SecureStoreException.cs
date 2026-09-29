namespace Engramic.Baseline.Platform;

/// <summary>
/// The data folder, or a file in it, cannot be trusted or used safely. The message says why and names
/// the path; nothing was changed to get round it.
/// </summary>
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
}
