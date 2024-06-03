{ pkgs, stdenv, pwninit ? pkgs.pwninit }:
let
  pwninit-template = pkgs.writeScriptBin "pwninit-template.py" ''
    #!${pkgs.python3}/bin/python3
    from pwn import *
    import pyperclip

    {bindings}

    context.binary = {bin_name}
    context.terminal = ['tmux', 'neww']

    gs = """
    """
    if args.REMOTE:
    	io = remote("addr", 1337)
    else:
    	with open("debug.gdb", "w+") as f:
    		f.write(gs)
    	if args.LOCALREMOTE:
    		io = remote("localhost", 13337)
    	else:
    		io = process({proc_args})
    		pyperclip.copy(f"pwndbg -p {io.pid} -x debug.gdb")

    def b():
    	input("waiting for you to attach gdb, continue?")

    def dbg(name, var):
      info(name + " = " + hex(var))

    b()

    # good luck pwning :)
    io.interactive()
  '';
in stdenv.mkDerivation {
  pname = "pwninit-template";
  version = "1.0";

  buildInputs = [ pkgs.makeWrapper ];

  doCheck = false;
  doInstallCheck = false;
  dontUnpack = true;

  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/pwninit
    cp ${pwninit-template}/bin/pwninit-template.py $out/share/pwninit/pwninit-template.py
    makeWrapper ${pwninit}/bin/pwninit $out/bin/pwnini \
    --add-flags "--template-path $out/share/pwninit/pwninit-template.py"
    runHook postInstall
  '';
}
