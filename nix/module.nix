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
  bleArgs =
    lib.optionals cfg.ble.enable (
      [
        "--ble-enable"
        "--btmgmt-path"
        "${cfg.ble.bluezPackage}/bin/btmgmt"
        "--ble-index"
        cfg.ble.index
        "--ble-instance"
        (toString cfg.ble.instance)
        "--ble-duration"
        (toString cfg.ble.duration)
        "--ble-length-flags"
        (toString cfg.ble.lengthFlags)
      ]
      ++ optionalArg "--ble-flags" cfg.ble.flags
      ++ optionalArg "--ble-nearby-action" cfg.ble.nearbyAction
      ++ optionalArg "--ble-nearby-info" cfg.ble.nearbyInfo
      ++ lib.concatMap (tlv: [
        "--ble-tlv"
        tlv
      ]) cfg.ble.tlvs
    );
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
    ++ optionalArg "--identity" cfg.identityPath
    ++ lib.concatMap (peer: [
      "--trusted-peer"
      peer
    ]) cfg.trustedPeers
    ++ lib.optionals cfg.allowUnknownPeer [ "--allow-unknown-peer" ]
    ++ optionalArg "--stream-bind" cfg.streamBind
    ++ optionalArg "--stream-advertise-addr" cfg.streamAdvertiseAddr
    ++ lib.concatMap (txt: [
      "--txt"
      txt
    ]) cfg.txt
    ++ bleArgs
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

    identityPath = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/var/lib/macolinux-uc/identity.json";
      description = "Path to the Linux PairVerify identity JSON used by the Rapport server.";
    };

    trustedPeers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "/var/lib/macolinux-uc/controller-peer.json" ];
      description = "Exported public peer identity JSON files allowed to complete PairVerify.";
    };

    allowUnknownPeer = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Allow PairVerify clients that are not present in trustedPeers. Experimental and unsafe.";
    };

    streamBind = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "0.0.0.0:0";
      description = "Bind address for inbound Universal Control stream listeners prepared after PairVerify.";
    };

    streamAdvertiseAddr = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "192.0.2.11";
      description = "Address returned in `_streamStart` responses. Defaults to the configured ipv4.";
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

    ble = {
      enable = lib.mkEnableOption "Apple Continuity BLE NearbyAction/NearbyInfo advertising";

      bluezPackage = lib.mkOption {
        type = lib.types.package;
        default = pkgs.bluez;
        description = "BlueZ package providing btmgmt.";
      };

      index = lib.mkOption {
        type = lib.types.str;
        default = "0";
        description = "BlueZ controller index, for example 0 for hci0.";
      };

      instance = lib.mkOption {
        type = lib.types.ints.between 1 254;
        default = 1;
        description = "BlueZ advertising instance ID.";
      };

      duration = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = 0;
        description = "Advertising timeout in seconds. Zero omits btmgmt -t and leaves the instance persistent.";
      };

      flags = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = "06";
        description = "BLE flags payload hex. Null disables the flags AD structure.";
      };

      lengthFlags = lib.mkOption {
        type = lib.types.ints.between 0 224;
        default = 0;
        description = "High three bits ORed into Continuity TLV length bytes.";
      };

      nearbyAction = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = "0102030405";
        description = "Continuity NearbyAction payload hex for TLV type 0x0f.";
      };

      nearbyInfo = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = "0000";
        description = "Continuity NearbyInfo payload hex for TLV type 0x10.";
      };

      tlvs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [
          "10:0000"
          "0f:0102030405"
        ];
        description = "Raw Continuity TLVs as TYPE:HEX entries.";
      };
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Additional command-line arguments for macolinux-ucd.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          cfg.identityPath != null
          || (cfg.trustedPeers == [ ] && cfg.allowUnknownPeer == false);
        message = "services.macolinux-uc.identityPath must be set when trustedPeers or allowUnknownPeer is enabled.";
      }
    ];

    environment.systemPackages = [ cfg.package ] ++ lib.optionals cfg.ble.enable [ cfg.ble.bluezPackage ];
    hardware.bluetooth.enable = lib.mkDefault cfg.ble.enable;

    systemd.services.macolinux-uc = {
      description = "macolinux Universal Control Linux peer daemon";
      wantedBy = [ "multi-user.target" ];
      after = [
        "network-online.target"
        "bluetooth.service"
      ];
      wants = [ "network-online.target" ];
      path = lib.optionals cfg.ble.enable [ cfg.ble.bluezPackage ];
      serviceConfig = {
        ExecStart = lib.escapeShellArgs serviceArgs;
        Restart = "on-failure";
        User = cfg.user;
        Group = cfg.group;
      };
    };
  };
}
