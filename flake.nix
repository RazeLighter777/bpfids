{
  description = "ebpf based ids/ips";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/*.tar.gz";
    rust-overlay.url = "https://flakehub.com/f/oxalica/rust-overlay/*.tar.gz";
  };

  outputs = {
    nixpkgs,
    rust-overlay,
    ...
  }: let
    allSystems = [
      "aarch64-linux"
      "x86_64-linux"
    ];

    forEachSystem = f:
      nixpkgs.lib.genAttrs allSystems (system:
        f {
          inherit system;
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              rust-overlay.overlays.default
            ];
          };
        });
  in {
    devShells = forEachSystem ({
      pkgs,
      system,
    }: {
      default = pkgs.mkShell {
        buildInputs = with pkgs; [
          linuxHeaders
          libbpf
        ];
        nativeBuildInputs = with pkgs; [
          llvmPackages_21.clang-unwrapped
          (rust-bin.stable.latest.default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
            ];
          })
          cargo
          rustfmt
          bear
          pkg-config
          bpftools
        ];
        shellHook = ''
          export CC=clang
          export CFLAGS="-O2 -Wall -Werror -Wno-unused-function -I${pkgs.linuxHeaders}/include $(pkg-config --cflags libbpf) -target bpf"
          export LDFLAGS="$(pkg-config --libs libbpf)"
        '';
      };
    });
  };
}
