# FiveM macOS Launcher

Der ARM64-AppKit-Wrapper startet die vorhandene lokale Installation über Python. Die installierte App liegt unter `/Applications/FiveM.app`. Die vorhandene Auth-Bridge 0.1.2 ist unter `Contents/Helpers` eingebettet; ihr Code verwendet weiterhin die bestehende hashgeprüfte Handoff-Datei im Projekt. Weder der Launcher noch die Bridge enthalten GTA oder Wine.

Version 0.1.1 enthält `NSMicrophoneUsageDescription` für FiveM-Sprachchat. Die Beschreibung ist auch für den gestarteten Wine-Prozess erforderlich: macOS ordnet dessen Mikrofonanfrage der startenden App zu. Ohne diesen Schlüssel wurde im lokalen Test ein TCC-Abbruch im Spielprozess nachgewiesen. Die Beschreibung erlaubt die reguläre Systemabfrage; sie erteilt keine Berechtigung. Beim ersten Start oder nach einer neuen lokalen Signatur können Dokumente- und Mikrofonfreigaben erneut abgefragt werden. Es werden keine TCC-Einträge geändert oder Berechtigungen automatisch erteilt.

Die lokale Konfiguration `~/Library/Application Support/FiveM macOS/launcher.json` enthält die absoluten Pfade `projectRoot` und `python`. Optional wählt `launcherRelativePath` einen Runner relativ zum Projektordner; ohne diesen Schlüssel gilt `native/client-profile/run_current.py`. Absolute Pfade, leere, `.`- und `..`-Komponenten sowie Symlink-Auflösungen außerhalb des Projektordners werden abgelehnt. Start und `--check` verwenden denselben Runner. Die Pfadprüfung ersetzt keine Integritätsprüfung des gewählten Runners.

```sh
/Applications/FiveM.app/Contents/MacOS/FiveMLauncher --self-test
/Applications/FiveM.app/Contents/MacOS/FiveMLauncher --check
```

`--self-test` nutzt temporäre harmlose Python-Fixtures; `--check` ruft den konfigurierten Runner mit `--check` auf und ist nur dann schreibgeschützt, wenn dieser Runner das gewährleistet. Das Fenster zeigt den Prozessstatus, ermöglicht nach Prozessende einen Neustart und verhindert parallele Starts durch dieselbe App-Instanz. Ein erneutes Öffnen startet erneut, wenn der überwachte Prozess beendet ist. Kein Timer beendet den Client.

Ein Build erfordert einen expliziten noch nicht vorhandenen Ausgabepfad sowie die bestehende signierte Bridge 0.1.2. Das Skript baut in einem temporären Ordner, entfernt diesen und erzeugt nur die angegebene App; es ersetzt keine bestehende App und registriert keine URL-Handler. Beispiel für eine kontrollierte Prüfung:

```sh
python3 -B native/macos-launcher/build.py --output /tmp/FiveM-test.app --auth-bridge '/Applications/FiveM.app/Contents/Helpers/FiveM Auth Bridge.app'
```

Die Test-App nach der Prüfung entfernen. Für Installation, LaunchServices-Registrierung und Überprüfung des `fivem://`-Handlers sind separate Schritte nötig. Der Build ist ad hoc signiert, nicht notarisiert. Protokolle liegen unter `~/Library/Logs/FiveM macOS/`; sie können sensible Prozessausgaben enthalten.
