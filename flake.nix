{
  description = "brrpolice build and OCI image pipeline";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      crane,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = pkgs.lib;
        craneLib = crane.mkLib pkgs;
        src = craneLib.cleanCargoSource ./.;

        commonArgs = {
          inherit src;
          strictDeps = true;
          CARGO_BUILD_INCREMENTAL = "false";
        };

        cargoArtifacts = craneLib.buildDepsOnly (
          commonArgs
          // {
            pname = "brrpolice-deps";
            version = "0.1.0";
            cargoBuildCommand = "cargo build --release --locked";
          }
        );

        brrpolice = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            pname = "brrpolice";
            version = "0.1.0";
            cargoBuildCommand = "cargo build --release --locked";
            doCheck = false;
          }
        );

        rootfs = pkgs.runCommand "brrpolice-rootfs" { } ''
          mkdir -p "$out/app" "$out/data"
          cp ${brrpolice}/bin/brrpolice "$out/app/brrpolice"
          chmod 0555 "$out/app/brrpolice"
          chmod 0770 "$out/data"
        '';

        ociImage = pkgs.dockerTools.buildLayeredImage {
          name = "brrpolice";
          tag = "latest";
          contents = [
            rootfs
            pkgs.cacert
          ];
          config = {
            User = "65532:65532";
            WorkingDir = "/app";
            Entrypoint = [ "/app/brrpolice" ];
            Env = [
              "BRRPOLICE_DATABASE__PATH=/data/brrpolice.sqlite"
              "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
            ];
            ExposedPorts = {
              "9090/tcp" = { };
            };
          };
        };

        publishImage = pkgs.writeShellApplication {
          name = "publish-image";
          runtimeInputs = [
            pkgs.nix
            pkgs.go-containerregistry
          ];
          text = ''
            set -euo pipefail

            if [ "$#" -ne 1 ]; then
              echo "usage: publish-image <image-ref>" >&2
              exit 2
            fi

            image_ref="$1"
            archive_path="$(nix build .#ociImage --print-out-paths --no-link)"
            crane push "$archive_path" "$image_ref"
          '';
        };
      in
      {
        packages =
          {
            inherit brrpolice;
            default = brrpolice;
          }
          // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
            inherit ociImage;
          };

        apps = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          publish-image = flake-utils.lib.mkApp { drv = publishImage; };
        };
      }
    );
}
