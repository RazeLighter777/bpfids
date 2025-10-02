{
  description = "ebpf based ids/ips";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/*.tar.gz";
    rust-overlay.url = "https://flakehub.com/f/oxalica/rust-overlay/*.tar.gz";
  };

  outputs =
    {
      nixpkgs,
      rust-overlay,
      ...
    }:
    let
      allSystems = [
        "aarch64-linux"
        "x86_64-linux"
      ];

      forEachSystem =
        f:
        nixpkgs.lib.genAttrs allSystems (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs {
              inherit system;
              overlays = [
                rust-overlay.overlays.default
              ];
            };
          }
        );
    in
    {
      devShells = forEachSystem (
        {
          pkgs,
          system,
        }:
        {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              linuxHeaders
              libbpf
              glibc.dev
              elfutils.dev
              zlib
            ];
            nativeBuildInputs = with pkgs; [
              llvmPackages_21.clang-unwrapped
              llvmPackages_21.libcxx
              llvmPackages_21.libllvm
              llvmPackages_21.clang-tools
              llvmPackages_21.clang
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
              export BPFCC=${pkgs.llvmPackages_21.clang-unwrapped}/bin/clang

              export BPFCFLAGS="-g -O2 -Wall -Werror -Wno-unused-function -I${pkgs.linuxHeaders}/include $(pkg-config --cflags libbpf) -target bpf"
              export BPFLDFLAGS="$(pkg-config --libs libbpf)"
              export CC=${pkgs.llvmPackages_21.clang}/bin/clang
              export CXX=${pkgs.llvmPackages_21.clang}/bin/clang++
            '';
            stdenv = pkgs.llvmPackages_21.stdenv;
          };
        }
      );
    };
}
