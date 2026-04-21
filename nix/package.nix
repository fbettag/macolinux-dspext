{
  lib,
  rustPlatform,
  src ? ../.,
}:

rustPlatform.buildRustPackage {
  pname = "macolinux-ucd";
  version = "0.1.0";

  inherit src;
  cargoLock.lockFile = src + "/Cargo.lock";

  meta = {
    description = "Linux Universal Control peer research daemon";
    license = with lib.licenses; [
      mit
      asl20
    ];
    mainProgram = "macolinux-ucd";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
