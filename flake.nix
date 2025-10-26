{
  description = "CTF Flake";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  inputs.pwndbg = {
    url = "github:pwndbg/pwndbg";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, pwndbg }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      stdenv = pkgs.stdenv;

      # ← Use pwndbg from its own flake
      pwndbg_downstream = pwndbg.packages.${system}.pwndbg;
    in {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          tmux
          gdb
          ltrace
          nasm
          one_gadget
          # pwndbg from upstream flake:
          pwndbg_downstream
          pwninit
          ropgadget
          socat
          strace
          curl
          qemu
          musl
          rubyPackages.seccomp-tools
          #burpsuite
          ghidra
          python3Packages.angr
          python3Packages.claripy
          python3Packages.ipython
          python3Packages.numpy
          python3Packages.pillow
          python3Packages.pwntools
          python3Packages.pycryptodome
          python3Packages.pyperclip
          python3Packages.requests
          python3Packages.scapy
          python3Packages.scipy
          python3Packages.seccomp
          python3Packages.tqdm
          python3Packages.z3
          python3Packages.ropper
          (import ./upload-kernel-exploit.nix { inherit pkgs; })
          # pass stdenv AND the pwndbg derivation into your wrapper:
          (import ./gdb-splitmind.nix {
            inherit pkgs stdenv;
            pwndbg = pwndbg_downstream;
          })
          (import ./pwninit.nix { inherit pkgs stdenv; })
        ];
      };
    };
}
