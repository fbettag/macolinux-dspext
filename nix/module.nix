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
        ExecStart = lib.escapeShellArgs ([ "${lib.getExe cfg.package}" "serve" ] ++ cfg.extraArgs);
        Restart = "on-failure";
        User = cfg.user;
        Group = cfg.group;
      };
    };
  };
}
