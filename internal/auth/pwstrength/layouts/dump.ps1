# Reads the Persian keyboard layouts of this Windows machine into the data files of this
# directory (rule strength-gate-corpus). Usage: powershell -File dump.ps1 <output dir>.
# It writes kbdfa.raw (layout 00000429, KBDFA.DLL) and isiri.raw (layout 00050429, the
# ISIRI 9147 "Persian (Standard)", kbdfar.dll): one line per key, tab separated, the scan
# code and the characters of that key on the US layout and on the Persian one, unshifted
# and shifted. isiri9147.tsv and kbdfa.tsv are these files under a comment header. It only
# reads: LoadKeyboardLayout with KLF_NOTELLSHELL does not switch the keyboard of the user.
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Kb {
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr LoadKeyboardLayout(string id, uint flags);
  [DllImport("user32.dll")] public static extern uint MapVirtualKeyEx(uint code, uint type, IntPtr hkl);
  [DllImport("user32.dll")] public static extern int ToUnicodeEx(uint vk, uint sc, byte[] state, [Out, MarshalAs(UnmanagedType.LPWStr, SizeConst=8)] StringBuilder buf, int n, uint flags, IntPtr hkl);
  public static string Get(IntPtr hkl, uint sc, bool shift, bool altgr) {
    uint vk = MapVirtualKeyEx(sc, 3, hkl);
    if (vk == 0) return "";
    byte[] st = new byte[256];
    if (shift) st[0x10] = 0x80;
    if (altgr) { st[0x11] = 0x80; st[0x12] = 0x80; }
    StringBuilder sb = new StringBuilder(8);
    int r = ToUnicodeEx(vk, sc, st, sb, 8, 4, hkl);
    if (r < 0) { // dead key: flush
      StringBuilder f = new StringBuilder(8);
      ToUnicodeEx(0x20, 0x39, new byte[256], f, 8, 4, hkl);
      return "DEAD";
    }
    if (r == 0) return "";
    return sb.ToString(0, r);
  }
}
'@
function Dump($id, $out) {
  $us = [Kb]::LoadKeyboardLayout("00000409", 0x80)
  $h = [Kb]::LoadKeyboardLayout($id, 0x80)
  $lines = @()
  $scs = @(0x29) + (2..0x0D) + (0x10..0x1B) + (0x1E..0x28) + @(0x2B) + (0x2C..0x35) + @(0x56, 0x39)
  foreach ($sc in $scs) {
    $row = @("{0:X2}" -f $sc)
    foreach ($l in @($us,$h)) {
      foreach ($sh in @($false,$true)) {
        $s = [Kb]::Get($l, [uint32]$sc, $sh, $false)
        $row += (($s.ToCharArray() | ForEach-Object { "U+{0:X4}" -f [int]$_ }) -join "+")
      }
    }
    $lines += ($row -join "`t")
  }
  [IO.File]::WriteAllLines($out, $lines)
}
$d = $args[0]
Dump "00000429" "$d\kbdfa.raw"
Dump "00050429" "$d\isiri.raw"
