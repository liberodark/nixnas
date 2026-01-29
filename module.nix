{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.nixnas;
in
{
  options.services.nixnas = {
    enable = lib.mkEnableOption "NixNAS web management daemon";

    package = lib.mkPackageOption pkgs "nixnas" { };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Port to listen on";
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0";
      description = "Address to bind to";
    };

    statePath = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/nixnas/state.json";
      description = "Path to state file";
    };

    nixOutputDir = lib.mkOption {
      type = lib.types.path;
      default = "/etc/nixos";
      description = "Directory for generated Nix configuration files";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.nixnas = {
      description = "NixNAS Web Management Daemon";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      path = with pkgs; [
        curl
        which
        iproute2
        util-linux
        uutils-coreutils
        smartmontools
        mdadm
        msmtp
        nixos-rebuild-ng
        btrfs-progs
        e2fsprogs
        xfsprogs
        dosfstools
        ntfs3g
        acl
        samba
        gawk
        gnugrep
        gptfdisk
        procps
        systemd
        zfs
      ];

      environment = {
        NIXNAS_LISTEN_ADDR = "${cfg.listenAddress}:${toString cfg.port}";
        NIXNAS_STATE_PATH = cfg.statePath;
        NIXNAS_NIX_OUTPUT_DIR = cfg.nixOutputDir;
        RUST_LOG = "nixnas_daemon=info";
        NIX_PATH = builtins.concatStringsSep ":" config.nix.nixPath;
      };

      serviceConfig = {
        ExecStart = lib.getExe cfg.package;
        StateDirectory = "nixnas";
        Restart = "on-failure";
        RestartSec = "5s";
      };
    };

    environment.systemPackages = [ cfg.package ];
  };
}
