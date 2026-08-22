/*
 * hook/observe-assetbundle.js - Windows Frida observer for game bundle reads
 *
 * Purpose: capture which anon/Bundles files the client actually opens at boot,
 * to determine the gamedata-Lua bundle (7d91430e vs 6edf14bb).
 * Uses only core Frida APIs (no il2cpp bridge).
 *
 * Anti-cheat: ACE(AntiCheatExpert) may kill Frida; stop the ACE service first
 * (see scripts/frida-observe.ps1).
 */
'use strict';

console.log('[*] observe-assetbundle started, pid=' + Process.id + ' arch=' + Process.arch);

const KEEP_RE = /[\\/](?:anon|Bundles)[\\/]/i;

function moduleByName(name) {
  for (const m of Process.enumerateModules()) {
    if (m.name === name) return m;
  }
  return null;
}

/* Parse full path from the OBJECT_ATTRIBUTES of NtCreateFile.
 * OBJECT_ATTRIBUTES: Length@0, RootDirectory@8, ObjectName{Length@0 MaxLength@2 Buffer@8}@+8. */
function readObjectPath(objectAttributes) {
  try {
    if (objectAttributes.isNull()) return null;
    const us = objectAttributes.add(8);
    const len = us.readU16();
    if (len === 0) return null;
    const buf = us.add(8).readPointer();
    if (buf.isNull()) return null;
    return buf.readUtf16String(len / 2) || null;
  } catch (e) {
    return null;
  }
}

// 1) NtCreateFile
const ntdll = moduleByName('ntdll.dll');
if (ntdll) {
  const p = ntdll.findExportByName('NtCreateFile');
  if (p) {
    Interceptor.attach(p, {
      onEnter(args) {
        const path = readObjectPath(args[1]);
        if (path && KEEP_RE.test(path)) console.log('[open] ' + path);
      }
    });
    console.log('[*] hooked NtCreateFile @ ' + p);
  } else {
    console.log('[!] NtCreateFile export not found');
  }
} else {
  console.log('[!] ntdll.dll not found');
}

// 2) Unity AssetBundle.LoadFromFile_Internal (best-effort)
const unity = moduleByName('UnityPlayer.dll');
if (!unity) {
  console.log('[!] UnityPlayer.dll not loaded yet');
} else {
  const candidates = [
    'AssetBundle_LoadFromFile_Internal',
    'UnityEngine_AssetBundle_LoadFromFile_Internal',
    'UnityEngine::AssetBundle::LoadFromFile_Internal'
  ];
  let hooked = false;
  for (const name of candidates) {
    const addr = unity.findExportByName(name);
    if (addr) {
      Interceptor.attach(addr, {
        onEnter(args) {
          try {
            console.log('[assetbundle] LoadFromFile ' + (args[0].readUtf16String() || '?'));
          } catch (e) {
            console.log('[assetbundle] LoadFromFile (unreadable)');
          }
        }
      });
      console.log('[*] hooked ' + name + ' @ ' + addr);
      hooked = true;
      break;
    }
  }
  if (!hooked) console.log('[!] AssetBundle.LoadFromFile_Internal export not found');
}