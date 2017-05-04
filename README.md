# PyDes

windows下编译：

`cl /LD /IC:\Python27\include PyDes.cpp C:\Python27\libs\python27.lib`

编译的结果是产生四个文件，分别是：PyDes.exp,PyDes.lib,PyDes.obj,PyDes.dll。将PyDes.dll改名为PyDes.pyd，然后就可以在python里面import这个模块了
