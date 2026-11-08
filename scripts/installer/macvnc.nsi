; MacVNC per-user Windows installer (NSIS 3, Unicode).
;
; Build after scripts/build-rust.ps1 -Package (see scripts/build-installer.ps1):
;   makensis /DVERSION=0.1.12 /DSOURCE=<absolute dist\macvnc-rust> /DOUTFILE=<absolute .exe> scripts\installer\macvnc.nsi
; makensis runs from this script's folder, so relative paths here start at scripts/installer.
;
; Installs per user into %LOCALAPPDATA%\Programs\MacVNC: no administrator prompt,
; and the folder stays writable so the in-app updater (docs/UPDATES.md) can
; replace the package in place. The uninstaller removes only files this package
; ships, never the whole chosen folder, so a mistaken install location is safe.

Unicode true
; Release builds use the standard x86 stub that every NSIS install ships.
; /DAMD64 builds a 64-bit stub (Linux makensis) for testing under 64-bit Wine.
!ifdef AMD64
  Target amd64-unicode
!endif
SetCompressor /SOLID lzma
RequestExecutionLevel user
ManifestDPIAware true

!ifndef VERSION
  !error "Pass /DVERSION=MAJOR.MINOR.PATCH"
!endif
!ifndef SOURCE
  !error "Pass /DSOURCE=<portable package folder>"
!endif
!ifndef OUTFILE
  !define OUTFILE "MacVNC-Setup-${VERSION}-win-x64.exe"
!endif

; Windows makensis does not expand a wildcard after a forward slash; Linux
; makensis needs one. Only the File wildcard depends on it.
!ifdef NSIS_WIN32_MAKENSIS
  !define SEP "\"
!else
  !define SEP "/"
!endif

!define APP "MacVNC"
!define EXE "macvnc-app.exe"
!define PUBLISHER "AnchorSprint"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"

Name "${APP} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\${APP}"
InstallDirRegKey HKCU "${UNINSTALL_KEY}" "InstallLocation"
BrandingText "${APP} ${VERSION} · ${PUBLISHER}"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APP}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "FileDescription" "${APP} installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "AGPL-3.0-or-later; see LICENSE-AGPL-3.0.txt"

!include "MUI2.nsh"
!include "LogicLib.nsh"

!define MUI_ICON "../../rust/crates/macvnc-app/assets/macvnc.ico"
!define MUI_UNICON "../../rust/crates/macvnc-app/assets/macvnc.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\${EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Start ${APP}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${SOURCE}/LICENSE-AGPL-3.0.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; The running app holds its executable open; Windows refuses to replace it.
!macro WaitForAppClosed
  ${If} ${FileExists} "$INSTDIR\${EXE}"
    retry:
    ClearErrors
    FileOpen $0 "$INSTDIR\${EXE}" a
    ${If} ${Errors}
      MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "${APP} is running. Close it, then click Retry." /SD IDCANCEL IDRETRY retry
      Abort
    ${EndIf}
    FileClose $0
  ${EndIf}
!macroend

Section "Install"
  !insertmacro WaitForAppClosed
  SetOutPath "$INSTDIR"
  ; A previous version's bundled source tree is replaced, not merged.
  RMDir /r "$INSTDIR\source"
  File /r "${SOURCE}${SEP}*.*"
  WriteUninstaller "$INSTDIR\Uninstall ${APP}.exe"

  CreateDirectory "$SMPROGRAMS\${APP}"
  CreateShortcut "$SMPROGRAMS\${APP}\${APP}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\${EXE}" 0
  CreateShortcut "$SMPROGRAMS\${APP}\Uninstall ${APP}.lnk" "$INSTDIR\Uninstall ${APP}.exe"
  CreateShortcut "$DESKTOP\${APP}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\${EXE}" 0

  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "URLInfoAbout" "https://github.com/ossmalaysia/macvnc"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\${EXE}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\Uninstall ${APP}.exe"'
  WriteRegStr HKCU "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall ${APP}.exe" /S'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  !insertmacro WaitForAppClosed
  Delete "$DESKTOP\${APP}.lnk"
  RMDir /r "$SMPROGRAMS\${APP}"

  ; Only what the package ships. Saved connection profiles live in the user's
  ; app-data folder and are kept, as with the portable package.
  Delete "$INSTDIR\${EXE}"
  Delete "$INSTDIR\*.dll"
  Delete "$INSTDIR\UPDATE.json"
  Delete "$INSTDIR\README.txt"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\LICENSE-AGPL-3.0.txt"
  Delete "$INSTDIR\FFMPEG-LICENSE.txt"
  Delete "$INSTDIR\FFMPEG-GPL-3.0.txt"
  Delete "$INSTDIR\THIRD_PARTY.md"
  Delete "$INSTDIR\.macvnc-update.lock"
  RMDir /r "$INSTDIR\source"
  Delete "$INSTDIR\Uninstall ${APP}.exe"
  RMDir "$INSTDIR"

  DeleteRegKey HKCU "${UNINSTALL_KEY}"
SectionEnd
