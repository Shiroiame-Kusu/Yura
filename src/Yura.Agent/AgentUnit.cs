using System.Globalization;
using System.Text;

namespace Yura.Agent;

/// <summary>
/// The systemd unit for the agent, generated rather than shipped.
/// </summary>
/// <remarks>
/// Generated so the unit names the options the administrator actually chose — the port, the
/// policy — instead of a file they have to remember to edit afterwards.
///
/// The hardening is chosen against what the agent does, which is very little: it opens
/// sockets and reads two files from its own state directory. It needs no capabilities, no
/// devices, no access to the rest of the filesystem and no privileged user, so it gets none
/// of them. Netlink is allowed only because <c>getaddrinfo</c> uses it to decide which address
/// families the host has.
/// </remarks>
internal static class AgentUnit
{
    public const string ServiceName = "yura-agent.service";

    public const string UnitPath = "/etc/systemd/system/" + ServiceName;

    public const string InstallPath = "/usr/local/lib/yura/yura-agent";

    public const string StateDirectoryName = "yura-agent";

    public const string StateDirectory = "/var/lib/" + StateDirectoryName;

    public static string Generate(AgentOptions options, string? name = null, string executable = InstallPath)
    {
        var command = new StringBuilder(executable);
        command.Append(" run --state ").Append(StateDirectory);
        if (name is { Length: > 0 })
        {
            // The service creates the identity on its first run, so a name given to install
            // has to reach the service; otherwise it is silently the host name instead.
            command.Append(" --name ").Append(name);
        }

        command.Append(CultureInfo.InvariantCulture, $" --listen {options.Listen} --port {options.Port}");
        if (options.UdpPort != 0 && options.UdpPort != options.Port)
        {
            command.Append(CultureInfo.InvariantCulture, $" --udp-port {options.UdpPort}");
        }

        if (!options.Udp)
        {
            command.Append(" --no-udp");
        }

        if (options.Policy.AllowPrivate)
        {
            command.Append(" --allow-private");
        }

        foreach (var network in options.Policy.Allowed)
        {
            command.Append(" --allow ").Append(network);
        }

        foreach (var network in options.Policy.Denied)
        {
            command.Append(" --deny ").Append(network);
        }

        if (options.Policy.Ports.Count > 0)
        {
            command.Append(" --ports ").Append(string.Join(',', options.Policy.Ports));
        }

        foreach (var own in options.Policy.LocalAddresses)
        {
            command.Append(" --own-address ").Append(own);
        }

        if (options.MaxSessions != new AgentOptions().MaxSessions)
        {
            command.Append(CultureInfo.InvariantCulture, $" --max-sessions {options.MaxSessions}");
        }

        if (!options.FullCone)
        {
            command.Append(" --no-full-cone");
        }
        else if (options.ConePorts != AgentOptions.DefaultConePorts)
        {
            command.Append(" --cone-ports ").Append(options.ConePorts);
        }

        return $"""
            [Unit]
            Description=Yura agent (game acceleration relay)
            After=network-online.target
            Wants=network-online.target

            [Service]
            Type=exec
            ExecStart={command}
            Restart=on-failure
            RestartSec=2

            # The agent runs as nobody in particular and keeps its keys in one directory
            # that only it can read.
            DynamicUser=yes
            StateDirectory={StateDirectoryName}
            StateDirectoryMode=0700

            # It opens sockets and reads its own two files. Everything else is taken away.
            NoNewPrivileges=yes
            CapabilityBoundingSet=
            AmbientCapabilities=
            ProtectSystem=strict
            ProtectHome=yes
            PrivateTmp=yes
            PrivateDevices=yes
            ProtectKernelTunables=yes
            ProtectKernelModules=yes
            ProtectKernelLogs=yes
            ProtectControlGroups=yes
            ProtectClock=yes
            ProtectProc=invisible
            RestrictNamespaces=yes
            RestrictRealtime=yes
            RestrictSUIDSGID=yes
            LockPersonality=yes
            SystemCallArchitectures=native
            # AF_NETLINK is here only because getaddrinfo asks the kernel which address
            # families exist; nothing else in the agent uses it.
            RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

            # One socket per relayed flow, so the default of 1024 is not enough.
            LimitNOFILE=65536

            [Install]
            WantedBy=multi-user.target

            """;
    }
}
