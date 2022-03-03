‘This script does a custom log shipping job using ROBOCOPY and VBScript
‘With FileSystemObject querying the sopecified folder for files created
‘within the past 15 minutes or less and generates a TSQL RESTORE LOG command
‘which is executed after the ROBOCOPY script
‘Syntax: RESTORE_LOG.vbs folder databaseName

On Error Resume Next

Dim fso, folder, files, sFolder, sFolderTarget, strParentFolder, strDatabaseName

Dim objShell

Set fso = CreateObject(“Scripting.FileSystemObject”)
Set objFSO = CreateObject(“Scripting.FileSystemObject”)

strParentFolder=Wscript.Arguments.Item(0)
strDatabaseName=Wscript.Arguments.Item(1)

sFolder = strParentFolder & strDatabaseName

Set folder = fso.GetFolder(sFolder)
Set files = folder.Files

SET objShell = CreateObject(“Wscript.Shell”)

For each itemFiles In files

a=sFolder & “” & itemFiles.Name

‘retrieve file extension

b = fso.GetExtensionName(a)

‘check if the file extension is TRN

If uCase(b)=”TRN” Then

‘check for DateCreated attribute of file and compare with current date/time

If (DateDiff(“N”, itemFiles.DateCreated, Now) <=15) Then ‘Create the file to contain the script If (objFSO.FileExists(“E:LogShipFolderscriptsSQL” & strDatabaseName & “.sql”)) Then objFSO.DeleteFile (“E:LogShipFolderscriptsSQL” & strDatabaseName & “.sql”) End If Set objMyFile = objFSO.CreateTextFile(“E:LogShipFolderscriptsSQL” & strDatabaseName & “.sql”, True) str1=”RESTORE LOG ” & strDatabaseName str2=”FROM DISK='” & a & “‘” str3=”WITH STANDBY=’E:LogShipFolderUNDOUNDO_” & strDatabaseName & “_ARCHIVE.DAT’,” str4=”DBO_ONLY” objMyFile.WriteLine (str1) objMyFile.WriteLine (str2) objMyFile.WriteLine (str3) objMyFile.WriteLine (str4) objMyFile.Close Set objFSO = Nothing Set objMyFile = Nothing ‘Run an OSQL command that uses a RESTORE LOG WITH MOVE, STANDBY objShell.Run(“osql -SinstanceName -E -iE:LogShipFolderscriptsSQL” & strDatabaseName & “.sql -oE:LogShipFolderscriptsSQL” & strDatabaseName & “_results.txt”) End If End If Next

objFile.Close
SET objFile = NOTHING
SET fso = NOTHING
SET folder = NOTHING
SET files = NOTHING
SET objShell = NOTHING
SET objFSO = NOTHING
SET objMyFile = NOTHING