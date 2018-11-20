# regsvr42

This is a tool for generating SxS manifests for Registration-Free COM (or "isolated" COM components) for native components. It is based on the original version by Cristian Adam available at https://www.codeproject.com/Articles/28682/regsvr42-Generate-SxS-Manifest-Files-from-Native-D

## Tool Usage
The basic usage is:

    regsvr42 com.dll

which will generate a file named `com.sxs.manifest`. You can find out what interfaces and coclasses the COM DLL exports.

When used with a client application the usage is:

    regsvr42 -client:client.exe com.dll

which will generate besides `com.sxs.manifest` another manifest file named `client.exe.manifest`. If `client.exe` already has a manifest file embedded, the contents of that manifest file are preserved into `client.exe.manifest` alongside with the reference to `com.sxs` assembly.

If you have more than one COM DLLs you want to use can use the tool in batch mode like:

    regsvr42 -client:client.exe -batch:file_containing_com_dll_file_names

You can put all the COM DLLs inside one directory and there will be just one manifest file inside the directory named `directory_name.manifest`

    regsvr42 -client:client.exe -dir:directory_with_com_dlls

If you have more than one directories with COM DLLs you can use the `-batch` function with all the names of the directories written in the batch file.

    regsvr42 -client:client.exe -batch:file_containing_directory_names
