using System;
using System.Text;

namespace FxSsh.Services.Sftp
{
    /// <summary>
    /// File attributes (ATTRS) as defined in draft-ietf-secsh-filexfer-02,
    /// section 5. A null field means the attribute is absent; the wire flags
    /// are computed from which fields are present.
    /// </summary>
    public sealed class SftpFileAttributes
    {
        private const uint AttrSize = 0x00000001;
        private const uint AttrUidGid = 0x00000002;
        private const uint AttrPermissions = 0x00000004;
        private const uint AttrAcmodeTime = 0x00000008;
        private const uint AttrExtended = 0x80000000;

        /// <summary>Gets or sets the file size in bytes; when applied through SETSTAT/FSETSTAT, a non-null value truncates or extends the file.</summary>
        public ulong? Size { get; set; }
        /// <summary>Gets or sets the numeric user ID (uid) of the file's owner.</summary>
        public uint? UserId { get; set; }
        /// <summary>Gets or sets the numeric group ID (gid) of the file's owning group.</summary>
        public uint? GroupId { get; set; }
        /// <summary>Gets or sets the POSIX permission bits, with the file type in the high bits (0x4000 directory, 0x8000 regular file, 0xA000 symbolic link) and the low nine bits holding the rwxrwxrwx mode.</summary>
        public uint? Permissions { get; set; }
        /// <summary>Gets or sets the last access time as seconds since the Unix epoch.</summary>
        public uint? AccessTime { get; set; }
        /// <summary>Gets or sets the last modification time as seconds since the Unix epoch.</summary>
        public uint? ModificationTime { get; set; }

        /// <summary>Vendor-specific attribute pairs ("name@domain", data).</summary>
        public (string Type, string Data)[] Extended { get; set; }

        /// <summary>Compute the wire-format flags for the fields that are present.</summary>
        public uint Flags
        {
            get
            {
                var flags = 0u;
                if (Size != null) flags |= AttrSize;
                if (UserId != null || GroupId != null) flags |= AttrUidGid;
                if (Permissions != null) flags |= AttrPermissions;
                if (AccessTime != null || ModificationTime != null) flags |= AttrAcmodeTime;
                if (Extended != null && Extended.Length > 0) flags |= AttrExtended;
                return flags;
            }
        }

        /// <summary>Read an ATTRS from the wire (section 5 field order).</summary>
        public static SftpFileAttributes Read(SshDataReader reader)
        {
            ArgumentNullException.ThrowIfNull(reader);

            var attr = new SftpFileAttributes();
            var flags = reader.ReadUInt32();
            if ((flags & AttrSize) != 0) attr.Size = reader.ReadUInt64();
            if ((flags & AttrUidGid) != 0)
            {
                attr.UserId = reader.ReadUInt32();
                attr.GroupId = reader.ReadUInt32();
            }
            if ((flags & AttrPermissions) != 0) attr.Permissions = reader.ReadUInt32();
            if ((flags & AttrAcmodeTime) != 0)
            {
                attr.AccessTime = reader.ReadUInt32();
                attr.ModificationTime = reader.ReadUInt32();
            }
            if ((flags & AttrExtended) != 0)
            {
                var count = reader.ReadUInt32();
                var extended = new (string, string)[count];
                for (var i = 0; i < count; i++)
                {
                    extended[i] = (reader.ReadString(Encoding.ASCII), reader.ReadString(Encoding.UTF8));
                }
                attr.Extended = extended;
            }
            return attr;
        }

        /// <summary>Write this ATTRS to the wire (section 5 field order).</summary>
        public void Write(SshDataWriter writer)
        {
            ArgumentNullException.ThrowIfNull(writer);

            writer.Write(Flags);
            if (Size != null) writer.Write(Size.Value);
            if (UserId != null) writer.Write(UserId.Value);
            if (GroupId != null) writer.Write(GroupId.Value);
            if (Permissions != null) writer.Write(Permissions.Value);
            if (AccessTime != null) writer.Write(AccessTime.Value);
            if (ModificationTime != null) writer.Write(ModificationTime.Value);
            if (Extended != null && Extended.Length > 0)
            {
                writer.Write((uint)Extended.Length);
                foreach (var (type, data) in Extended)
                {
                    writer.Write(type, Encoding.ASCII);
                    writer.Write(data, Encoding.UTF8);
                }
            }
        }
    }
}
