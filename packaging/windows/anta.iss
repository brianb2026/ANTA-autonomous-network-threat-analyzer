; Inno Setup script for ANTA (built by packaging/build.py on Windows).
; Per-user install: no administrator rights needed to install or run.
#ifndef AppVersion
  #define AppVersion "0.2.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\ANTA"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif
#ifndef OutputName
  #define OutputName "ANTA-setup"
#endif

[Setup]
AppId={{588A4C44-FD73-4BE1-BF0F-8E4764FF6BE6}
AppName=ANTA
AppVersion={#AppVersion}
AppPublisher=ANTA
AppComments=Autonomous Network Threat Analyzer
DefaultDirName={localappdata}\Programs\ANTA
DefaultGroupName=ANTA
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename={#OutputName}
SetupIconFile=..\icons\anta.ico
UninstallDisplayIcon={app}\ANTA.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{autoprograms}\ANTA"; Filename: "{app}\ANTA.exe"
Name: "{autodesktop}\ANTA"; Filename: "{app}\ANTA.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\ANTA.exe"; Description: "Launch ANTA"; Flags: nowait postinstall skipifsilent

[Code]
function NpcapInstalled(): Boolean;
begin
  Result := RegKeyExists(HKLM, 'SOFTWARE\Npcap') or RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Npcap')
            or FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ErrorCode: Integer;
begin
  if (CurStep = ssPostInstall) and not NpcapInstalled() then
  begin
    if MsgBox('ANTA can analyse capture files right away. To capture live traffic it needs Npcap, ' +
              'the free Windows packet capture driver (also used by Wireshark).' + #13#10#13#10 +
              'Open npcap.com to download it now?', mbConfirmation, MB_YESNO) = IDYES then
      ShellExec('open', 'https://npcap.com/#download', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
  end;
end;
