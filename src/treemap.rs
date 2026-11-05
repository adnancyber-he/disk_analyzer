// src/treemap.rs
use egui::{Pos2, Rect};

pub fn squarify(bounds: Rect, weights: &[f64]) -> Vec<(usize, Rect)> {
    let mut result = Vec::new();
    if weights.is_empty() || bounds.width() <= 0.0 || bounds.height() <= 0.0 {
        return result;
    }

    let mut items: Vec<(usize, f64)> = weights
        .iter()
        .enumerate()
        .filter(|&(_, w)| *w > 0.0)
        .map(|(i, w)| (i, *w))
        .collect();

    if items.is_empty() {
        return result;
    }

    items.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let total: f64 = items.iter().map(|(_, w)| w).sum();
    layout_slice(bounds, &items, total, &mut result);
    result
}

fn layout_slice(area: Rect, items: &[(usize, f64)], total: f64, out: &mut Vec<(usize, Rect)>) {
    if items.is_empty() {
        return;
    }
    if items.len() == 1 {
        out.push((items[0].0, area));
        return;
    }

    let half = total / 2.0;
    let mut acc = 0.0;
    let mut cut = 0;
    for (i, &(_, w)) in items.iter().enumerate() {
        if acc + w > half && i > 0 {
            break;
        }
        acc += w;
        cut = i + 1;
    }
    cut = cut.clamp(1, items.len() - 1);

    let (left, right) = items.split_at(cut);
    let left_weight: f64 = left.iter().map(|(_, w)| w).sum();
    let frac = (left_weight / total) as f32;

    let (rect_a, rect_b) = if area.width() >= area.height() {
        let xm = area.min.x + area.width() * frac;
        (
            Rect::from_min_max(area.min, Pos2::new(xm, area.max.y)),
            Rect::from_min_max(Pos2::new(xm, area.min.y), area.max),
        )
    } else {
        let ym = area.min.y + area.height() * frac;
        (
            Rect::from_min_max(area.min, Pos2::new(area.max.x, ym)),
            Rect::from_min_max(Pos2::new(area.min.x, ym), area.max),
        )
    };

    layout_slice(rect_a, left, left_weight, out);
    layout_slice(rect_b, right, total - left_weight, out);
}