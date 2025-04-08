{ pkgs, stdenv, gdb ? pkgs.gdb, pwndbg ? pkgs.pwndbg }:
let
  splitmindSrc = pkgs.fetchFromGitHub {
    owner = "jerdna-regeiz";
    repo = "splitmind";
    rev = "master";
    sha256 = "RsPU8tmBjQevAdGU5WgPRsxvPe5gZ+TU07Ol4oYCWaU=";
  };
in stdenv.mkDerivation {
  pname = "gdb-splitmind";
  version = "1.0";

  src = splitmindSrc;

  buildInputs = [ pkgs.python3Packages.setuptools pkgs.makeWrapper pkgs.tmux ];

  doCheck = false;
  doInstallCheck = false;

  gdbinit = pkgs.writeText "$out/share/gdbinit" ''
    set follow-fork-mode parent
    set show-flags on
    python
    import splitmind
    (splitmind.Mind(splitter=splitmind.Tmux(cmd="cat -"))
     .right(display="regs")
     .below(of="regs", display="stack")
    ).build()
    end
    set context-code-lines 10
    set context-source-code-lines 5
    set context-stack-lines 12
    set context-sections  "args code disasm stack backtrace"
  '';
  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/splitmind
    cp -r * $out/share/splitmind
    echo "source $out/share/splitmind/gdbinit.py" > $out/share/gdbinit
    cat $gdbinit >> $out/share/gdbinit
    makeWrapper ${pwndbg}/bin/pwndbg $out/bin/g \
    --add-flags "--command=$out/share/gdbinit"
    runHook postInstall
  '';
}
