using System;

namespace FxSsh.Algorithms.Catalog
{
    /// <summary>
    /// A single algorithm catalog entry.
    /// </summary>
    /// <remarks>
    /// The <see cref="Factory"/> argument is the instantiation input for the
    /// negotiated name: host key factories receive the PEM private key that
    /// SshServer.AddHostKey registered under that name; every other category
    /// receives null and implementations ignore it. The argument is never the
    /// algorithm's catalog name, so an alias negotiated under its own name
    /// behaves identically to its target.
    /// </remarks>
    public record AlgorithmDefine<T>(string Name, AlgorithmTag Tag, bool Supported, Func<string, T> Factory)
    {
        /// <summary>
        /// Converts the (Name, Tag, Supported, Factory) tuple form into an
        /// <see cref="AlgorithmDefine{T}"/>, enabling tuple entries in
        /// collection initializers.
        /// </summary>
        /// <param name="t">The tuple to convert.</param>
        /// <returns>A new <see cref="AlgorithmDefine{T}"/> built from the tuple's fields.</returns>
        public static implicit operator AlgorithmDefine<T>((string Name, AlgorithmTag Tag, bool Supported, Func<string, T> Factory) t)
            => new(t.Name, t.Tag, t.Supported, t.Factory);
    }
}
