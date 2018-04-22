# Python program to format C/C++ files using clang-format
import os
 
# File Extension filter. You can add new extension
cpp_extensions = (".cxx",".cpp",".c", ".hxx", ".hh", ".cc", ".hpp")
 
# Set the current working directory for scanning c/c++ sources (including
# header files) and apply the clang formatting
# Please note "-style" is for standard style options
# and "-i" is in-place editing
for root, dirs, files in os.walk(os.getcwd()):
    for file in files:
        if file.endswith(cpp_extensions):
            os.system("clang-format-3.5 -i -style=file " + root + "/" + file)
