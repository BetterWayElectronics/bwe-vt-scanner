# BwE VT Analysis

Basically a quick and easy Virus Total scanner which can be attached as a context menu item within Windows. Compiled for x64.

Create the following in the registry:

* Computer\HKEY_CLASSES_ROOT\*\shell\BwE VT Analysis\
* @="BwE VT Analysis"
* Computer\HKEY_CLASSES_ROOT\*\shell\BwE VT Analysis\Command
* @="C:\WHEREVERYOUWANTEDIT\BwE_VT_Analysis.exe "%1""


![Github Logo](https://i.imgur.com/4QgbBnh.png)
