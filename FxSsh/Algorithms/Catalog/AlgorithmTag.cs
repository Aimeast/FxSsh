namespace FxSsh.Algorithms.Catalog
{
    /// <summary>
    /// Classifies a catalog entry's origin and negotiability. Only entries not
    /// tagged <see cref="Disable"/> survive
    /// <see cref="AlgorithmCollectionBuilder{T}.BuildCollection"/>, i.e.
    /// enter negotiation.
    /// </summary>
    public enum AlgorithmTag
    {
        /// <summary>
        /// Excluded from negotiation while remaining in the catalog. Legacy
        /// algorithms are seeded in this state;
        /// <see cref="AlgorithmCollectionBuilder{T}.Enable(string)"/> flips an
        /// entry to <see cref="Obsolete"/>.
        /// </summary>
        Disable,

        /// <summary>
        /// A shipped algorithm, negotiable by default.
        /// </summary>
        BuiltIn,

        /// <summary>
        /// A negotiable legacy algorithm, re-enabled from
        /// <see cref="Disable"/> via
        /// <see cref="AlgorithmCollectionBuilder{T}.Enable(string)"/>; the
        /// startup log warns about it.
        /// </summary>
        Obsolete,

        /// <summary>
        /// An alternate name for another entry, snapshotting the target's
        /// definition at alias creation time (created with
        /// <see cref="AlgorithmCollectionBuilder{T}.AddAlias(string, string)"/>).
        /// </summary>
        Alias,

        /// <summary>
        /// A user-contributed algorithm registered with
        /// <see cref="AlgorithmCollectionBuilder{T}.Add(string, System.Func{string, T})"/>.
        /// </summary>
        Custom,
    }
}
