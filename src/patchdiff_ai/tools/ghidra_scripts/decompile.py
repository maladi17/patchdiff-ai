from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def _norm(token):
    stripped = token.upper().lstrip("0")
    return stripped or "0"


def main():
    args = getScriptArgs()
    if len(args) < 2:
        raise RuntimeError("usage: decompile.py <out_dir> <ea> [<ea>...]")

    out_dir = args[0]
    monitor = ConsoleTaskMonitor()
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    function_manager = currentProgram.getFunctionManager()

    for token in args[1:]:
        addr = toAddr("0x" + _norm(token))
        function = function_manager.getFunctionContaining(addr)
        if function is None:
            function = function_manager.getFunctionAt(addr)
        if function is None:
            print("[!] No function found for %s" % token)
            continue

        result = decompiler.decompileFunction(function, 60, monitor)
        if not result.decompileCompleted():
            print("[!] Decompilation failed for %s: %s" % (token, result.getErrorMessage()))
            continue
        decompiled = result.getDecompiledFunction()
        if decompiled is None:
            print("[!] No decompiled output for %s" % token)
            continue

        dst = "%s/%s.c" % (out_dir.replace("\\", "/"), _norm(token))
        handle = open(dst, "w")
        try:
            handle.write(decompiled.getC())
            handle.write("\n")
        finally:
            handle.close()

    decompiler.dispose()


if __name__ == "__main__":
    main()
