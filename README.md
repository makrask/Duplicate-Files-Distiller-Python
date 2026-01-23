# Duplicate-Files-Distiller-Python

# 🚀 Description

This program separates the files of a folder (the working folder) into two parts A and B.
It uses a third folder with files as a reference point (checkpoint).
Any files of the working folder that are anywhere in the checkpoint folder are transferred to a third folder (bin), preserving the structure of the working folder.
After completing the process, we have two sets of files, one in the working folder and one in the bin folder.
The files that are left in the working folder either do not exist anywhere in the reference folder (checkpoint), or are different from the corresponding files in the reference folder

This means:
**from A evaporate C to B distilling A'**
```
A-C=B+A'
```

That is:
If we consider that we have two data sets (organized in a tree form) A and C, **we can define an operation** between them called distill as follows:
```
A-C=B+A'
```
so that any element of A contained in C is transferred to B with the same tree structure.
The result is three trees A', C, B and it is true that A = A' + B (A' union B).


# 🧰 Notes

The script generates a hash for each file, so it does not compare based on name, modification date, or anything else. 
It does not delete any files; it simply moves them elsewhere while preserving the original path, so you can restore the initial state with a copy.
It creates a log file in the folder where it is executed.


# 💸 Support Me

If you liked the project and want to support me:

<a href='https://ko-fi.com/E1E01KVQEY' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://storage.ko-fi.com/cdn/kofi6.png?v=6' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>


# 📄 License
This project is available under the MIT License. See the LICENSE file for more information.

