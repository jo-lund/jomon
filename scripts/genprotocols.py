#!/usr/bin/env python3

import os

header = "/* Autogenerated - do not edit */\n\n"

def create_files():
    path = os.getcwd() + "/decoder"
    files = sorted(os.listdir(path))
    fr = open(path + "/register.h", 'w')
    fd = open(path + "/decoder.h", 'w')
    fr.write(header)
    fr.write("#ifndef DECODER_REGISTER_H\n")
    fr.write("#define DECODER_REGISTER_H\n\n")
    fr.write("#include \"decoder.h\"\n\n")
    fr.write("typedef void (*register_function)(void);\n")
    fr.write('static register_function decoder_functions[] = {\n')
    fd.write(header)
    fd.write("#ifndef DECODER_H\n")
    fd.write("#define DECODER_H\n\n")
    for fn in files:
        basename = os.path.basename(fn)
        if basename.startswith('packet_') and basename.endswith('.c'):
            names = basename[:-2].split('_')
            fr.write("    register_%s,\n" % names[1])
            fd.write("#include \"packet_%s.h\"\n" % names[1])
    fr.write('};\n')
    fr.write("#endif\n")
    fd.write("#endif\n")
    fr.close()
    fd.close()

if __name__ == "__main__":
    create_files()
