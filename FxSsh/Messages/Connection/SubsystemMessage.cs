﻿using FxSsh.Messages.Connection;
using System.Text;

namespace FxSsh.Messages
{
    public class SubsystemMessage : ChannelRequestMessage
    {
        public string Name { get; private set; }

        protected override void OnLoad(SshDataWorker reader)
        {
            base.OnLoad(reader);

            Name = reader.ReadString(Encoding.ASCII);
        }
    }
}