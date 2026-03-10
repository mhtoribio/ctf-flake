{ pkgs }:
pkgs.writeShellScriptBin "get-libs" ''
  exec ${pkgs.python3}/bin/python3 ${./scripts/get-libs.py} "$@"
''
