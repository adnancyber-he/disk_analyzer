// src/scanner.rs
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use filesize::PathExt;

#[derive(Debug, Clone)]
pub struct FileNode {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub apparent: u64,
    pub is_dir: bool,
    pub is_link: bool,
    pub ext: String,
    pub children: Vec<FileNode>,
}

pub fn scan_dir(path: &PathBuf) -> FileNode {
    let mut children = Vec::new();
    let mut total_size = 0u64;
    let mut total_apparent = 0u64;

    if let Ok(entries) = fs::read_dir(path) {
        let entries_vec: Vec<_> = entries.filter_map(|e| e.ok()).collect();

        let scanned: Vec<FileNode> = entries_vec
            .par_iter()
            .filter_map(|entry| {
                let file_name = entry.file_name().to_string_lossy().to_string();
                let entry_path = entry.path();

                let sym_meta = entry_path.symlink_metadata().ok()?;
                let is_link = sym_meta.file_type().is_symlink();

                if is_link {
                    return Some(FileNode {
                        name: file_name,
                        path: entry_path,
                        size: 0,
                        apparent: 0,
                        is_dir: false,
                        is_link: true,
                        ext: String::new(),
                        children: Vec::new(),
                    });
                }

                let metadata = entry.metadata().ok()?;

                if metadata.is_dir() {
                    let mut sub = scan_dir(&entry_path);
                    sub.name = file_name;
                    Some(sub)
                } else {
                    let real = entry_path
                        .size_on_disk_fast(&metadata)
                        .unwrap_or_else(|_| metadata.len());
                    let apparent = metadata.len();
                    let ext = entry_path
                        .extension()
                        .map(|e| e.to_string_lossy().to_lowercase())
                        .unwrap_or_default();

                    Some(FileNode {
                        name: file_name,
                        path: entry_path,
                        size: real,
                        apparent,
                        is_dir: false,
                        is_link: false,
                        ext,
                        children: Vec::new(),
                    })
                }
            })
            .collect();

        for child in scanned {
            total_size += child.size;
            total_apparent += child.apparent;
            children.push(child);
        }

        children.sort_by(|a, b| b.size.cmp(&a.size));
    }

    FileNode {
        name: path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string_lossy().to_string()),
        path: path.clone(),
        size: total_size,
        apparent: total_apparent,
        is_dir: true,
        is_link: false,
        ext: String::new(),
        children,
    }
}

pub fn aggregate_by_ext(node: &FileNode) -> Vec<(String, u64, u64)> {
    let mut map: HashMap<String, (u64, u64)> = HashMap::new();
    fn walk(n: &FileNode, map: &mut HashMap<String, (u64, u64)>) {
        for c in &n.children {
            if c.is_dir && !c.is_link {
                walk(c, map);
            } else if !c.is_dir {
                let key = if c.ext.is_empty() { "(no ext)".into() } else { c.ext.clone() };
                let e = map.entry(key).or_insert((0, 0));
                e.0 += c.size;
                e.1 += 1;
            }
        }
    }
    walk(node, &mut map);
    let mut v: Vec<_> = map.into_iter().map(|(k, (s, c))| (k, s, c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v
}

pub fn suspicious_ext(ext: &str) -> bool {
    matches!(
        ext,
        "exe" | "scr" | "pif" | "com" | "msi" | "dll" | "cpl" | "ocx" | "sys"
        | "bat" | "cmd" | "ps1" | "psm1" | "vbs" | "vbe" | "js" | "jse"
        | "wsf" | "wsh" | "hta" | "sh" | "jar" | "apk" | "lnk" | "reg" | "inf"
        | "docm" | "xlsm" | "pptm" | "dotm" | "xlam"
        | "zip" | "rar" | "7z" | "iso" | "img" | "vhd" | "vhdx"
    )
}

pub fn reviewable_source_ext(ext: &str) -> bool {
    matches!(
        ext,
        "c" | "h" | "cpp" | "cc" | "cxx" | "hpp"
        | "asm" | "s"
        | "rs" | "py" | "rb" | "pl" | "php" | "lua" | "go" | "cs" | "java"
        | "vb" | "vbs" | "sh" | "bash" | "ps1" | "bat" | "cmd"
    )
}

#[derive(Clone)]
pub struct ContentHit {
    pub path: PathBuf,
    pub score: u32,
    pub matched: Vec<&'static str>,
}

const INDICATORS: &[(&str, u32, &str)] = &[
    ("_popen",              3, "remote shell via _popen"),
    ("CreateProcessA",      2, "process spawn"),
    ("WinExec",             3, "process spawn (WinExec)"),
    ("ShellExecute",        3, "process spawn (ShellExecute)"),
    ("inet_addr",           2, "hardcoded C2 IP"),
    ("connect(",            1, "outbound socket connect"),
    ("recv(",               1, "socket receive"),
    ("send(",               1, "socket send"),
    ("RegSetValueEx",       3, "registry persistence"),
    ("CurrentVersion\\Run", 3, "Run-key persistence"),
    ("CreateService",       3, "service persistence"),
    ("schtasks",            2, "scheduled task persistence"),
    ("IsDebuggerPresent",   3, "anti-debug"),
    ("CheckRemoteDebuggerPresent", 3, "anti-debug"),
    ("cpuid",               2, "CPUID hypervisor check"),
    ("GetTickCount",        1, "timing check / sleep obfuscation"),
    ("GetModuleFileName",   2, "self-path discovery"),
    ("CopyFile",            2, "self-copy"),
    ("SetFileAttributes",   2, "hide via attributes"),
    ("CryptEncrypt",        3, "Windows crypto API encryption"),
    ("CryptGenKey",         3, "key generation"),
    ("WriteFile",           1, "file write"),
    ("MoveFile",            1, "file rename"),
    ("Login Data",          3, "browser credential path"),
    ("lsass",               3, "LSASS access"),
    ("MiniDumpWriteDump",   4, "credential dump"),
    ("SetWindowsHookEx",    4, "keyboard hook"),
    ("GetAsyncKeyState",    4, "keystroke capture"),
    ("VirtualAllocEx",      3, "remote memory allocation"),
    ("WriteProcessMemory",  4, "process injection"),
    ("CreateRemoteThread",  4, "remote thread injection"),
    ("LoadLibrary",         1, "DLL load"),
    ("GetProcAddress",      1, "dynamic API resolution"),
];

pub fn scan_content(path: &PathBuf) -> Option<ContentHit> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > 2 * 1024 * 1024 { return None; }
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8(bytes).ok()?;

    let mut score = 0u32;
    let mut matched = Vec::new();
    for (pat, weight, label) in INDICATORS {
        if text.contains(pat) {
            score += weight;
            matched.push(*label);
        }
    }
    if score == 0 { return None; }
    Some(ContentHit { path: path.clone(), score, matched })
}