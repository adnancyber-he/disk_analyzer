// src/main.rs
mod scanner;
mod treemap;

use eframe::egui;
use egui::{Color32, Sense, Stroke};
use scanner::{
    aggregate_by_ext, reviewable_source_ext, scan_content, scan_dir,
    suspicious_ext, ContentHit, FileNode,
};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Duration;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 800.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Rust Disk Analyzer (Read-Only Forensic Mode)",
        options,
        Box::new(|_cc| Ok(Box::<DiskAnalyzerApp>::default())),
    )
}

struct ScanResult {
    root: FileNode,
}

#[derive(PartialEq, Clone, Copy)]
enum SideTab {
    Extensions,
    Suspicious,
    Content,
    Largest,
}

struct DiskAnalyzerApp {
    root: Option<FileNode>,
    view_stack: Vec<FileNode>,
    scanning: bool,
    scan_rx: Option<Receiver<ScanResult>>,
    side_tab: SideTab,
    use_real_size: bool,
    status: String,
    content_hits: Vec<ContentHit>,
}

impl Default for DiskAnalyzerApp {
    fn default() -> Self {
        Self {
            root: None,
            view_stack: Vec::new(),
            scanning: false,
            scan_rx: None,
            side_tab: SideTab::Extensions,
            use_real_size: true,
            status: "Ready. Read-only: no write, no delete, no execute.".into(),
            content_hits: Vec::new(),
        }
    }
}

impl DiskAnalyzerApp {
    fn current_view(&self) -> Option<&FileNode> {
        self.view_stack.last().or(self.root.as_ref())
    }

    fn start_scan(&mut self, path: PathBuf) {
        if self.scanning { return; }
        self.scanning = true;
        self.root = None;
        self.view_stack.clear();
        self.content_hits.clear();
        self.status = format!("Scanning (read-only): {}", path.display());

        let (tx, rx) = mpsc::channel();
        self.scan_rx = Some(rx);

        std::thread::spawn(move || {
            let root = scan_dir(&path);
            let _ = tx.send(ScanResult { root });
        });
    }

    fn poll_scan(&mut self) -> bool {
        let Some(rx) = &self.scan_rx else { return false; };
        match rx.try_recv() {
            Ok(result) => {
                let root = result.root;

                let mut candidates: Vec<PathBuf> = Vec::new();
                fn walk(n: &FileNode, out: &mut Vec<PathBuf>) {
                    for c in &n.children {
                        if c.is_dir && !c.is_link {
                            walk(c, out);
                        } else if !c.is_dir && reviewable_source_ext(&c.ext) {
                            out.push(c.path.clone());
                        }
                    }
                }
                walk(&root, &mut candidates);

                let mut hits: Vec<ContentHit> = Vec::new();
                for p in &candidates {
                    if let Some(hit) = scan_content(p) {
                        hits.push(hit);
                    }
                }
                hits.sort_by(|a, b| b.score.cmp(&a.score));

                let flagged = hits.len();
                self.content_hits = hits;
                self.root = Some(root.clone());
                self.view_stack = vec![root];
                self.scanning = false;
                self.scan_rx = None;
                self.status = format!(
                    "Scan complete. {} source file(s) matched malware indicators. No files modified.",
                    flagged
                );
                true
            }
            Err(TryRecvError::Empty) => false,
            Err(TryRecvError::Disconnected) => {
                self.scanning = false;
                self.scan_rx = None;
                self.status = "Scan thread disconnected.".into();
                true
            }
        }
    }

    fn export_csv(&mut self, node: &FileNode) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name("disk_report.csv")
            .save_file()
        else { return; };

        let mut out = String::from("path,name,is_dir,real_bytes,apparent_bytes,ext,is_link\n");
        fn walk(n: &FileNode, out: &mut String) {
            for c in &n.children {
                out.push_str(&format!(
                    "\"{}\",\"{}\",{},{},{},\"{}\",{}\n",
                    c.path.display(),
                    c.name.replace('"', "\"\""),
                    c.is_dir,
                    c.size,
                    c.apparent,
                    c.ext,
                    c.is_link
                ));
                if c.is_dir && !c.is_link {
                    walk(c, out);
                }
            }
        }
        walk(node, &mut out);
        let _ = std::fs::write(&path, out);
        self.status = format!("CSV exported: {}", path.display());
    }

    fn export_html(&mut self, node: &FileNode) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name("disk_report.html")
            .save_file()
        else { return; };

        let exts = aggregate_by_ext(node);
        let mut html = String::from(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Disk Report</title>\
             <style>body{font-family:system-ui;margin:24px}table{border-collapse:collapse;width:100%}\
             th,td{border:1px solid #ccc;padding:6px 10px;text-align:left}th{background:#eee}\
             .warn{color:#b00;font-weight:bold}.src{color:#c80;font-weight:bold}</style></head><body>",
        );
        html.push_str(&format!(
            "<h1>Disk Analysis Report</h1><p>Root: <code>{}</code><br>\
             Total real size: {} bytes<br>Total apparent size: {} bytes<br>\
             Generated: {}</p>",
            node.path.display(),
            node.size,
            node.apparent,
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        ));

        html.push_str("<h2>Malware-Indicator Matches in Source Files</h2>");
        if self.content_hits.is_empty() {
            html.push_str("<p>No matches.</p>");
        } else {
            html.push_str("<table><tr><th>File</th><th>Score</th><th>Indicators</th></tr>");
            for hit in &self.content_hits {
                html.push_str(&format!(
                    "<tr class=\"warn\"><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                    hit.path.display(),
                    hit.score,
                    hit.matched.join("; ")
                ));
            }
            html.push_str("</table>");
        }

        html.push_str("<h2>Suspicious Executable / Script Extensions</h2><table><tr><th>Ext</th><th>Size</th><th>Count</th></tr>");
        let mut any_susp = false;
        for (ext, size, count) in &exts {
            if suspicious_ext(ext) {
                any_susp = true;
                html.push_str(&format!(
                    "<tr class=\"warn\"><td>.{}</td><td>{}</td><td>{}</td></tr>",
                    ext, size, count
                ));
            }
        }
        if !any_susp {
            html.push_str("<tr><td colspan=\"3\">None found.</td></tr>");
        }
        html.push_str("</table>");

        html.push_str("<h2>All Extensions</h2><table><tr><th>Ext</th><th>Size</th><th>Count</th></tr>");
        for (ext, size, count) in &exts {
            let class = if suspicious_ext(ext) {
                " class=\"warn\""
            } else if reviewable_source_ext(ext) {
                " class=\"src\""
            } else {
                ""
            };
            html.push_str(&format!(
                "<tr{}><td>.{}</td><td>{}</td><td>{}</td></tr>",
                class, ext, size, count
            ));
        }
        html.push_str("</table></body></html>");

        let _ = std::fs::write(&path, html);
        self.status = format!("HTML report exported: {}", path.display());
    }
}

impl eframe::App for DiskAnalyzerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let arrived = self.poll_scan();
        if self.scanning && !arrived {
            ctx.request_repaint_after(Duration::from_millis(120));
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("📂 Scan Folder (Read-Only)").clicked() && !self.scanning {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.start_scan(p);
                    }
                }
                if ui.button("⬆ Up").clicked() && self.view_stack.len() > 1 {
                    self.view_stack.pop();
                }
                ui.separator();
                ui.checkbox(&mut self.use_real_size, "Real on-disk size");
                ui.separator();
                if ui.button("📄 Export CSV").clicked() {
                    if let Some(v) = self.current_view() { let v = v.clone(); self.export_csv(&v); }
                }
                if ui.button("🌐 Export HTML").clicked() {
                    if let Some(v) = self.current_view() { let v = v.clone(); self.export_html(&v); }
                }
                if self.scanning {
                    ui.spinner();
                    ui.label("Scanning…");
                }
            });
        });

        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
            });
        });

        if let Some(view) = self.current_view() {
            let view = view.clone();
            let content_hits_snapshot = self.content_hits.clone();

            egui::SidePanel::left("side")
                .resizable(true)
                .default_width(360.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.side_tab, SideTab::Extensions, "Extensions");
                        ui.selectable_value(&mut self.side_tab, SideTab::Suspicious, "⚠ Suspicious");
                        ui.selectable_value(&mut self.side_tab, SideTab::Content, "🔍 Content");
                        ui.selectable_value(&mut self.side_tab, SideTab::Largest, "Largest");
                    });
                    ui.separator();

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        match self.side_tab {
                            SideTab::Extensions => {
                                for (ext, size, count) in aggregate_by_ext(&view) {
                                    let class_note = if suspicious_ext(&ext) {
                                        " ⚠"
                                    } else if reviewable_source_ext(&ext) {
                                        " 📝"
                                    } else {
                                        ""
                                    };
                                    ui.label(format!(
                                        ".{}{}  —  {} files  —  {} B",
                                        ext, class_note, count, size
                                    ));
                                }
                            }
                            SideTab::Suspicious => {
                                let exts = aggregate_by_ext(&view);
                                let mut any = false;

                                for (ext, size, count) in &exts {
                                    if suspicious_ext(ext) {
                                        any = true;
                                        ui.colored_label(
                                            Color32::from_rgb(220, 60, 60),
                                            format!(
                                                "⚠ .{}  —  {} files  —  {} B  (executable/script)",
                                                ext, count, size
                                            ),
                                        );
                                    }
                                }

                                ui.separator();
                                ui.label("Source code — review, do not execute:");
                                for (ext, size, count) in &exts {
                                    if reviewable_source_ext(ext) && !suspicious_ext(ext) {
                                        any = true;
                                        ui.colored_label(
                                            Color32::from_rgb(200, 140, 40),
                                            format!(
                                                "📝 .{}  —  {} files  —  {} B",
                                                ext, count, size
                                            ),
                                        );
                                    }
                                }

                                if !any {
                                    ui.label("No suspicious or source extensions in this view.");
                                }
                            }
                            SideTab::Content => {
                                if content_hits_snapshot.is_empty() {
                                    ui.label("No malware indicators found in reviewable source files.");
                                } else {
                                    ui.colored_label(
                                        Color32::from_rgb(220, 60, 60),
                                        format!(
                                            "{} file(s) matched malware indicators:",
                                            content_hits_snapshot.len()
                                        ),
                                    );
                                    ui.separator();
                                    for hit in &content_hits_snapshot {
                                        let name = hit
                                            .path
                                            .file_name()
                                            .map(|s| s.to_string_lossy().to_string())
                                            .unwrap_or_default();
                                        let header = format!("{}  (score {})", name, hit.score);
                                        egui::CollapsingHeader::new(header)
                                            .default_open(hit.score >= 10)
                                            .show(ui, |ui| {
                                                ui.label(hit.path.display().to_string());
                                                for m in &hit.matched {
                                                    ui.colored_label(
                                                        Color32::from_rgb(200, 140, 40),
                                                        format!("  • {}", m),
                                                    );
                                                }
                                            });
                                    }
                                }
                            }
                            SideTab::Largest => {
                                let mut files: Vec<&FileNode> = Vec::new();
                                fn collect<'a>(n: &'a FileNode, out: &mut Vec<&'a FileNode>) {
                                    for c in &n.children {
                                        if c.is_dir && !c.is_link {
                                            collect(c, out);
                                        } else if !c.is_dir {
                                            out.push(c);
                                        }
                                    }
                                }
                                collect(&view, &mut files);
                                files.sort_by(|a, b| b.size.cmp(&a.size));
                                for f in files.iter().take(50) {
                                    ui.label(format!("{}  —  {} B", f.name, f.size));
                                }
                            }
                        }
                    });
                });
        }

        let mut pending_drill: Option<FileNode> = None;
        let content_hits_for_treemap = self.content_hits.clone();
        let use_real_size = self.use_real_size;

        egui::CentralPanel::default().show(ctx, |ui| {
            let Some(view) = self.current_view() else {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        "Select a folder to analyze. This tool only reads metadata; \
                         it never modifies your disk.",
                    );
                });
                return;
            };

            ui.horizontal(|ui| {
                ui.label(format!("📁 {}", view.path.display()));
                ui.label(format!(
                    "| Real: {} B | Apparent: {} B",
                    view.size, view.apparent
                ));
            });
            ui.separator();

            if view.children.is_empty() {
                ui.label("(empty or no readable children)");
                return;
            }

            let available = ui.available_rect_before_wrap();
            let painter = ui.painter_at(available);

            let weights: Vec<f64> = view
                .children
                .iter()
                .map(|c| {
                    (if use_real_size { c.size } else { c.apparent }).max(1) as f64
                })
                .collect();
            let layout = treemap::squarify(available, &weights);

            for (idx, rect) in layout {
                let child = &view.children[idx];

                let flagged = content_hits_for_treemap
                    .iter()
                    .any(|h| h.path == child.path);

                let color = if child.is_link {
                    Color32::from_rgb(180, 140, 60)
                } else if child.is_dir {
                    Color32::from_rgb(70, 130, 180)
                } else if suspicious_ext(&child.ext) {
                    Color32::from_rgb(180, 60, 60)
                } else if flagged {
                    Color32::from_rgb(200, 40, 40)
                } else if reviewable_source_ext(&child.ext) {
                    Color32::from_rgb(180, 120, 40)
                } else {
                    Color32::from_rgb(100, 100, 100)
                };

                painter.rect_filled(rect, 0.0, color);
                painter.rect_stroke(rect, 0.0, Stroke::new(1.0_f32, Color32::BLACK));

                if rect.width() > 80.0 && rect.height() > 24.0 {
                    let shown = if use_real_size { child.size } else { child.apparent };
                    painter.text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        format!("{}\n{} B", child.name, shown),
                        egui::FontId::proportional(12.0),
                        Color32::WHITE,
                    );
                }

                let resp = ui.interact(rect, ui.id().with(idx), Sense::click());
                if resp.clicked() && child.is_dir && !child.is_link {
                    pending_drill = Some(child.clone());
                }
            }
        });

        if let Some(node) = pending_drill {
            self.view_stack.push(node);
        }
    }
}