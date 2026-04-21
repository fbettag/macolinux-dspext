{
  description = "Linux Universal Control peer research and daemon";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{
      self,
      flake-parts,
      nixpkgs,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem =
        {
          pkgs,
          system,
          ...
        }:
        let
          macolinux-ucd = pkgs.callPackage ./nix/package.nix { src = self; };
        in
        {
          formatter = pkgs.nixfmt;

          packages = {
            inherit macolinux-ucd;
            default = macolinux-ucd;
          };

          apps = {
            macolinux-ucd = {
              type = "app";
              program = "${macolinux-ucd}/bin/macolinux-ucd";
              meta.description = "Run the macolinux Universal Control daemon skeleton";
            };
            default = self.apps.${system}.macolinux-ucd;
          };

          devShells.default = pkgs.mkShell {
            packages =
              with pkgs;
              [
                cargo
                clippy
                rustc
                rustfmt
                pkg-config
              ]
              ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
                dbus
                bluez
                avahi
                linuxHeaders
              ];
          };

          checks.default = macolinux-ucd;
        };

      flake.nixosModules.default = import ./nix/module.nix { inherit self; };
    };
}
