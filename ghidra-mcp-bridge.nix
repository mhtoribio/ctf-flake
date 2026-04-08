{ pkgs }:
let
  py = pkgs.python3.withPackages (
    ps: with ps; [
      mcp
      requests
    ]
  );
in
pkgs.writeShellScriptBin "ghidra-mcp-bridge" ''
  exec ${py}/bin/python3 ${./scripts/bridge_mcp_ghidra.py} "$@"
''
