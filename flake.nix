{
  description = "CTF Flake";

  #####################
  # Flake inputs
  #####################
  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

  # Upstream pwndbg flake. We DON'T make it follow our nixpkgs,
  # so it runs with the versions it pins (via the app).
  inputs.pwndbg.url = "github:pwndbg/pwndbg";

  #####################
  # Flake outputs
  #####################
  outputs = { self, nixpkgs, pwndbg }:
    let
      # If you only target x86_64-linux, keep this as-is.
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      stdenv = pkgs.stdenv;

      py = pkgs.python3.withPackages (ps: with ps; [
            angr
            claripy
            gmpy2
            ipython
            numpy
            pillow
            pwntools
            pycryptodome
            pyperclip
            requests
            scapy
            scipy
            seccomp
            tqdm
            z3-solver
            ropper
          ]);

      # Wrapper that runs the *pwndbg app* from the upstream flake in its own closure.
      # This avoids mixing with your shell's Python/capstone.
      pwndbgApp = pkgs.writeShellApplication {
        name = "pwndbg";
        text = ''
          # Keep pwndbg isolated from the shell's Python
          exec env -u PYTHONPATH -u PYTHONHOME \
            nix run --accept-flake-config ${pwndbg}#pwndbg -- "$@"
        '';
      };
    in {
      #####################
      # Dev shell
      #####################
      devShells.${system}.default = pkgs.mkShell {
        # Your tool stack
        buildInputs = with pkgs; [
          tmux
          gdb
          ltrace
          nasm
          one_gadget
          pwninit
          ropgadget
          socat
          strace
          curl
          qemu
          musl
          rubyPackages.seccomp-tools
          # burpsuite
          ghidra

		  # Python interpreter with packages
		  py

          # Your local derivations / wrappers
          (import ./get-libs.nix { inherit pkgs; })
          (import ./upload-kernel-exploit.nix { inherit pkgs; })
          (import ./gdb-splitmind.nix {
            inherit pkgs stdenv;
            pwndbgLauncher = pwndbgApp;
          })
          (import ./pwninit.nix { inherit pkgs stdenv; })

          # Put the pwndbg launcher on PATH (calls the upstream flake app)
          pwndbgApp
        ];
      };
    };
}
