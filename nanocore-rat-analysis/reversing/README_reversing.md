# Reverse Engineering — NanoCore RAT v1.2.2.0

## Lab Setup

| Component | Version | Purpose |
|-----------|---------|---------|
| FLARE-VM | Feb 2026 | Isolated Windows analysis VM |
| VMware Workstation | 17 Player | Hypervisor |
| Detect It Easy (DIE) | v3.10 | PE identification |
| strings.exe | v2.54 | String extraction |
| dnSpy | v6.5.1 | .NET decompiler + debugger |
| Process Monitor | Sysinternals | System call monitoring |
| Wireshark | Latest | Network capture |
| Regshot | Latest | Registry snapshot comparison |

---

## 5-Phase Pipeline

```
Phase 01 → Environment Setup (FLARE-VM, FakeNet-NG, internet enabled)
Phase 02 → Static Analysis  (DIE, strings.exe, PE header inspection)
Phase 03 → Decompile        (dnSpy Assembly Explorer, de4dot deobfuscation)
Phase 04 → Dynamic Analysis (ProcMon filter, Wireshark capture, Regshot)
Phase 05 → Detection Eng.   (IOC extraction, YARA rules, SIEM SPL, MITRE mapping)
```

> Phases are **iterative** — dynamic findings loop back to refine static analysis.

---

## Binary Identification

```
File:           sample.exe (desktop) → drops LqxOPFPGhCh.exe (%AppData%\Roaming)
Format:         PE32, .NET CLR 4.0.30319, C#, Visual Studio
File size:      609 KB
Compile time:   54E927A1 → Feb 22, 2015 06:19:37 AM UTC
Assembly GUID:  d1078431-3e19-48f3-9a9b-3846df9ed245
Entry point:    ClientLoaderForm.Main()
Timestamp:      2022-02-22 (PE header)
```

---

## Obfuscation Analysis

### 1. Symbol Renaming
All class/method names replaced with `#=qXxx==` Base64-like sequences.
- 71 TypeDefs renamed
- 464 methods renamed
- Requires de4dot to normalise: `de4dot.exe sample.exe -o cleaned.exe`

### 2. [DebuggerHidden] on Every Method
```csharp
[DebuggerHidden]
[EditorBrowsable(EditorBrowsableState.Never)]
internal static void #=qXxx==() { ... }
```
Standard debuggers skip these — requires IL-level breakpoints.

### 3. Opaque Predicates (Always-true/false branches)
```csharp
if (3 != 0) { ... }   // always true
if (-1 == 0) { ... }  // always false
if (true) { ... }     // always true
if (!false) { ... }   // always true
```
Hundreds of dead branches to confuse decompilers.

### 4. [GeneratedCode] + [HideModuleName]
```csharp
[GeneratedCode("MyTemplate", "8.0.0.0")]
[StandardModule]
[HideModuleName]
internal sealed class #=qXxx== { ... }
```
Makes class appear to be VB.NET auto-generated boilerplate.

### 5. [EditorBrowsable(Never)]
Hides methods from IDE IntelliSense and tooling.

### 6. Constant Obfuscation
String literals replaced with computed field references.

---

## Key Reverse Engineering Findings

### Finding 1: Entry Point (ClientLoaderForm)
```csharp
// Token: 0x02000044 RID: 68
public class ClientLoaderForm : Form
{
    public ClientLoaderForm()
    {
        base.FormClosing += this.#=qHandler==;
        base.Shown       += this.#=qShownHandler==;
        Application.EnableVisualStyles();
        if (3 != 0)  // opaque predicate
        {
            #=qXxx== = this;
        }
        this.ShowInTaskbar  = false;        // stealth: hidden from taskbar
        this.WindowState    = FormWindowState.Minimized;  // stealth: minimized
    }

    [STAThread]
    public static void Main()
    {
        Application.Run(#=qNew==().#=qCreate==());
    }

    private void #=qShownHandler==(object sender, EventArgs e)
    {
        if (false) { }      // dead branch
        this.Visible = false;               // stealth: window hidden
        #=qC2Setup==.#=qSaveMefStateAsync==(config);  // C2 connection
    }
}
```

### Finding 2: Run Key Persistence (smethod_11)
```csharp
// Class8, smethod_11 — sets the Run key path
private static void smethod_11()
{
    Class8.string_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
}
```
→ **MITRE T1547.001**

### Finding 3: Scheduled Task (smethod_47)
```csharp
private static bool smethod_47(string string_4, string string_5, int int_2)
{
    try
    {
        string tempFileName = Path.GetTempFileName();
        string string_5_1 = string.Format("/create /f /tn \"{0}\" /xml \"{1}\"",
                                           (object)string_4,
                                           (object)tempFileName);
        System.IO.File.WriteAllText(tempFileName, string_5);
        Process process = Process.Start(Class8.smethod_50("schtasks.exe"), string_5_1);
        // ...
    }
}
```
→ **MITRE T1053.005**

### Finding 4: C2 Setup Chain
```
FormShown() → SaveMefStateAsync(CompositionConfiguration) → TcpClient.BeginConnect(host, port)
```
`CompositionConfiguration` holds the hardcoded C2 host + port in obfuscated fields.

### Finding 5: 138-Combo Persistence
See `nanocore_pattern_generator.py` for full reconstruction.

---

## Dynamic Analysis Results

### ProcMon Observations
```
LqxOPFPGhCh.exe (PID 6900)
├── UDP Send: 192.168.19.140:57529 → 8.8.4.4   [DNS beacon]
├── CreateFile: %AppData%\Roaming\LqxOPFPGhCh.exe   [self-copy confirmed]
└── Thread Exit: TID 2556, SUCCESS   [82,565 total events captured]

lsass.exe (PID 680)
└── QueryNameInfo: C:\Users\Shard\AppData\Local\...   [credential access indicator]
```

### Wireshark Observations (22 packets)
```
TCP  52191 → 5985  [SYN] Seq=0 Win=65535   [C2 WinRM probe]
TCP  5985  → 52191 [RST] Seq=1 Ack=1       [connection refused — C2 offline]
UDP  57529 → 53    8.8.4.4                  [DNS beacon]
```

### Regshot Results
```
Keys deleted:        20,331
Keys added:          37,081   ← massive persistence footprint
Values deleted:      23,840
Values added:       113,215   ← configuration + startup entries
Values modified:         33
TOTAL CHANGES:      194,500
```

### Dropped Binary Properties
```
Path:              C:\Users\Shard\AppData\Roaming\LqxOPFPGhCh.exe
Size:              609 KB
File description:  Novartis         ← fake metadata
Product name:      Novartis
Copyright:         Copyright © 2011
Original filename: hKcs.exe         ← reveals true origin
```

---

## IOCs (Indicators of Compromise)

| Type | Value |
|------|-------|
| **File** | `LqxOPFPGhCh.exe` (609 KB, PE32 .NET) |
| **Path** | `C:\Users\*\AppData\Roaming\LqxOPFPGhCh.exe` |
| **PE Metadata** | Description: `Novartis`, Copyright: `© 2011`, Original: `hKcs.exe` |
| **Registry** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\[one of 138 names]` |
| **Scheduled Task** | Name matches Run key name (e.g. `TCP Monitor`) |
| **Network** | UDP → `8.8.4.4:53` (DNS), TCP SYN → port `5985` |
| **Process** | `LqxOPFPGhCh.exe` (PID 6900), `cmd.exe` (PID 6288) |
| **WER Artifact** | `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\AppCrash_LqxOPFPGhCh.exe` |

---

## Limitations

| Severity | Issue |
|----------|-------|
| HIGH | `CompositionConfiguration` class found but C2 host/port fields not extracted |
| MED | `BaseCommand`, `FileCommand`, `PluginCommand` not decompiled |
| MED | `de4dot` cleaned binary not re-analysed in dnSpy |
| LOW | No live breakpoints set at `TcpClient.Connect` — runtime C2 IP not captured |
| LOW | Specific Run key written during this run not extracted from Regshot report |
