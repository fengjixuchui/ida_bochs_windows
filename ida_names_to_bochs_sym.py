# by David Reguera Garcia aka Dreg
# https://github.com/therealdreg/ida_bochs_windows
# https://www.fr33project.org - dreg@fr33project.org @therealdreg 

filename = ida_kernwin.ask_file(True, "*.txt", "Select file to save symbols")

with open(filename, "w+") as file:
    i = 0
    print("\n")
    for addr, name in Names():
        inf = hex(addr) + " " + name + "\n"
        file.write(inf)
        if i < 10:
            print(inf)
        i += 1
    print("...\n")
    print("done symbols saved -> ", filename)
        
# Type in bochs debugger: ldsym global "C:\\Users\\Dreg\\bochs\\sym.txt"