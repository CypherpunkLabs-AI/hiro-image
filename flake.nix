{
  description = "Pinned h-image OS build and application-release tooling";
  inputs.nixpkgs.url = "github:nixos/nixpkgs/c5ae371f1a6a7fd27823bc500d9390b38c05fa55";
  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      diskTools = with pkgs; [ cryptsetup dosfstools e2fsprogs mtools squashfsTools zstd ];
      builder = pkgs.mkosi.override { extraDeps = diskTools ++ [ pkgs.apt pkgs.dpkg pkgs.gnupg ]; };
      search = pkgs.buildEnv {
        name = "h-image-tools";
        paths = builder.dependencies;
        pathsToLink = [ "/bin" ];
        ignoreCollisions = true;
      };
      mkosi = pkgs.writeShellScriptBin "mkosi" ''
        exec ${builder}/bin/mkosi --extra-search-path=${search}/bin "$@"
      '';
      systemd = pkgs.systemd.override { withUkify = true; withBootloader = true; };
      ukify = pkgs.writeShellScriptBin "ukify" ''
        exec ${systemd}/lib/systemd/ukify "$@"
      '';
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [ mkosi ukify qemu_test apt dpkg binutils util-linux gptfdisk
          python3 go git gzip gnutar coreutils gh openssl ] ++ diskTools;
        H_IMAGE_OVMF = "${pkgs.OVMF.fd}/FV/OVMF_CODE.fd";
        H_IMAGE_OVMF_VARS = "${pkgs.OVMF.fd}/FV/OVMF_VARS.fd";
      };
    };
}
