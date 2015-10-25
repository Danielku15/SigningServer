namespace SigningServer.Contracts
{
    public enum SignFileResponseResult
    {
        /// <summary>
        /// File was successfully signed
        /// </summary>
        FileSigned,
        /// <summary>
        /// Files was successfully signed, an existing signature was removed
        /// </summary>
        FileResigned,
        /// <summary>
        /// The file was already signed and therefore signing was skipped. 
        /// </summary>
        FileAlreadySigned,
        /// <summary>
        /// The file was not signed because the given file format cannot be signed or is not supported.
        /// </summary>
        FileNotSignedUnsupportedFormat,
        /// <summary>
        /// The file was not signed because an unexpected error happened.
        /// </summary>
        FileNotSignedError,
        /// <summary>
        /// The file was not signed because the singing request was noth authorized.
        /// </summary>
        FileNotSignedUnauthorized
    }
}