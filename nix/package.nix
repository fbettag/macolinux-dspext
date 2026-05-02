{
  lib,
  stdenv,
  rustPlatform,
  apple-sdk,
  src ? ../.,
}:

let
  version = "0.1.0";
in
rustPlatform.buildRustPackage {
  pname = "macolinux-ucd";
  inherit version;

  inherit src;
  cargoLock.lockFile = src + "/Cargo.lock";

  buildInputs = lib.optionals stdenv.isDarwin [ apple-sdk ];

  postInstall = lib.optionalString stdenv.isDarwin ''
    $CC -fobjc-arc -fblocks \
      -framework Foundation \
      -framework Network \
      -framework Security \
      ${src}/research/tools/network-actor-framer-probe.m \
      -o $out/bin/macolinux-network-actor-framer-probe

    $CC \
      -framework Network \
      -framework Security \
      ${src}/research/tools/network-endpoint-c-probe.c \
      -o $out/bin/macolinux-network-endpoint-c-probe

    $CC -fobjc-arc -fblocks \
      -framework Foundation \
      -framework Network \
      -framework Security \
      ${src}/research/tools/continuity-inspect.m \
      -o $out/bin/macolinux-continuity-inspect

    $CC -fobjc-arc -fblocks \
      -framework Foundation \
      ${src}/research/tools/companion-service-probe.m \
      -o $out/bin/macolinux-companion-service-probe

    $CC -fobjc-arc -fblocks \
      -framework Foundation \
      -framework ApplicationServices \
      ${src}/research/tools/macos-input-forwarder.m \
      -o $out/bin/macolinux-macos-input-forwarder

    app_dir="$out/Applications/MacolinuxBootstrap.app/Contents"
    mkdir -p "$app_dir/MacOS"

    cp $out/bin/macolinux-uc-bootstrap "$app_dir/MacOS/"
    cp $out/bin/pairverify_actor_helper "$app_dir/MacOS/"
    cp $out/bin/macolinux-network-actor-framer-probe "$app_dir/MacOS/"
    cp $out/bin/macolinux-network-endpoint-c-probe "$app_dir/MacOS/"
    cp $out/bin/macolinux-continuity-inspect "$app_dir/MacOS/"
    cp $out/bin/macolinux-companion-service-probe "$app_dir/MacOS/"
    cp $out/bin/macolinux-macos-input-forwarder "$app_dir/MacOS/"

    cat > "$app_dir/Info.plist" <<'EOF'
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
      "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
      <dict>
        <key>CFBundleDevelopmentRegion</key>
        <string>en</string>
        <key>CFBundleExecutable</key>
        <string>macolinux-uc-bootstrap</string>
        <key>CFBundleIdentifier</key>
        <string>io.github.fbettag.macolinux.bootstrap</string>
        <key>CFBundleInfoDictionaryVersion</key>
        <string>6.0</string>
        <key>CFBundleName</key>
        <string>MacolinuxBootstrap</string>
        <key>CFBundlePackageType</key>
        <string>APPL</string>
        <key>CFBundleShortVersionString</key>
        <string>${version}</string>
        <key>CFBundleVersion</key>
        <string>${version}</string>
        <key>LSBackgroundOnly</key>
        <true/>
      </dict>
    </plist>
    EOF
  '';

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
