{
  description = "ebpf based ids/ips";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in
    {
      packages.default = pkgs.callPackage ./default.nix { };
      defaultPackage = self.packages.default;
      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          llvmPackages_21.clangUseLLVM
        ];
      };
    };
}
