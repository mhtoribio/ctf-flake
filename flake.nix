{
  description = "CTF Flake";

  inputs = { nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable"; };

  outputs = { self, nixpkgs }@inputs:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          tmux
          gdb
          ltrace
          nasm
          one_gadget
          pwndbg
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
          python311Packages.angr
          python311Packages.claripy
          python311Packages.gmpy2
          python311Packages.ipython
          python311Packages.numpy
          python311Packages.pillow
          python311Packages.pwntools
          python311Packages.pycryptodome
          python311Packages.pyperclip
          python311Packages.requests
          python311Packages.scapy
          python311Packages.scipy
          python311Packages.seccomp
          python311Packages.tqdm
          python311Packages.z3
          python311Packages.ropper
          (import ./upload-kernel-exploit.nix { inherit pkgs; })
          (import ./gdb-splitmind.nix { inherit pkgs stdenv; })
          (import ./pwninit.nix { inherit pkgs stdenv; })
        ];

      };
    };
}
