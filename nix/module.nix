{ self ? null }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.macolinux-uc;
  system = pkgs.stdenv.hostPlatform.system;
  defaultPackage =
    if self != null && builtins.hasAttr system self.packages then
      self.packages.${system}.macolinux-ucd
    else
      pkgs.callPackage ./package.nix { src = ../.; };
  optionalArg = flag: value: lib.optionals (value != null) [
    flag
    value
  ];
  serviceArgs =
    [
      "${lib.getExe cfg.package}"
      "serve"
      "--instance"
      cfg.instance
      "--port"
      (toString cfg.port)
    ]
    ++ optionalArg "--hostname" cfg.hostname
    ++ optionalArg "--ipv4" cfg.ipv4
    ++ optionalArg "--multicast-ipv4" cfg.multicastIpv4
    ++ optionalArg "--ble-address" cfg.bleAddress
    ++ lib.concatMap (txt: [
      "--txt"
      txt
    ]) cfg.txt
    ++ cfg.extraArgs;
in
{
  options.services.macolinux-uc = {
    enable = lib.mkEnableOption "macolinux Universal Control Linux peer daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = defaultPackage;
      description = "Package providing the macolinux-ucd binary.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "root";
      description = "User to run the daemon as. Root is expected for uinput and Bluetooth access.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "root";
      description = "Group to run the daemon as.";
    };

    instance = lib.mkOption {
      type = lib.types.str;
      default = "linux-peer";
      description = "CompanionLink Bonjour service instance name.";
    };

    hostname = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "linux-peer.local";
      description = "mDNS host name to advertise. Defaults to instance.local.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 49152;
      description = "TCP port for the CompanionLink probe listener.";
    };

    ipv4 = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "192.0.2.11";
      description = "IPv4 address to publish in mDNS. Defaults to the primary route address.";
    };

    multicastIpv4 = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "192.0.2.11";
      description = "IPv4 interface address used for mDNS multicast. Defaults to ipv4.";
    };

    bleAddress = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "02:00:00:00:00:31";
      description = "Bluetooth address to publish as CompanionLink rpBA.";
    };

    txt = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [
        "rpFl=0xffffffff"
        "rpMd=MacBookPro18,3"
      ];
      description = "CompanionLink TXT key/value overrides or additions.";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Additional command-line arguments for macolinux-ucd.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    systemd.services.macolinux-uc = {
      description = "macolinux Universal Control Linux peer daemon";
      wantedBy = [ "multi-user.target" ];
      after = [
        "network-online.target"
        "bluetooth.service"
      ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        ExecStart = lib.escapeShellArgs serviceArgs;
        Restart = "on-failure";
        User = cfg.user;
        Group = cfg.group;
      };
    };
  };
}
