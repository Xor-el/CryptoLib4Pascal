# CryptoLib4Pascal — lightweight brand guide

## Primary mark

- **Default:** [`logo.svg`](logo.svg) — **encrypt flow**: rounded **plaintext** panel (three lines), **cyan chevron**, **ciphertext** block (dark field with lighter “byte” squares). Reads as **encryption** and a **crypto library**, not a single algorithm.
- **Dark UI:** [`logo-dark.svg`](logo-dark.svg) — same layout with **brighter** plaintext panel and lines, **sky** chevron, **near-black** ciphertext panel and **slate** squares on the deep badge.

## Palette (default logo)

| Role | Hex | Notes |
|------|-----|--------|
| Badge top | `#0f4d6e` | Gradient start. |
| Badge bottom | `#082f45` | Gradient end — same as legacy grid mark. |
| Badge gradient axis | `(0,0)–(1,1)` | Diagonal like the legacy mark (not vertical). |
| Plaintext panel | `#3d8fb0` at 95% opacity | Same treatment as legacy mid grid cells. |
| Plaintext lines | `#e8f4fc` | Same as legacy light grid cells (stroke). |
| Arrow | `#38bdf8` | Transform direction. |
| Ciphertext field | `#062a3c` | Dark output panel (encrypt-flow only). |
| Ciphertext tiles | `#3d8fb0` at 95% opacity | Same as legacy mid cells on the dark field. |

Dark variant uses `#0a1624`–`#050c14`, panel `#155e75`, lines `#cffafe`, arrow `#22d3ee`, field `#020617`, tiles `#334155`.

**Banner background** (flat fill behind the logo for wide social and Open Graph PNGs [here](export/)): RGB **16, 77, 110** (`#104d6e`) — same deep teal as `#0f4d6e` to the eye; +1 red avoids matching the badge top pixel-for-pixel so the squircle edge survives. The **SVG** keeps gradient top `#0f4d6e`.

## Typography (pairing)

The logo has **no embedded wordmark**. When setting type next to the mark:

- Prefer **clean sans-serif** system or UI fonts (e.g. Segoe UI, Inter, Source Sans 3).
- **Do not** use Embarcadero’s proprietary Delphi logotype fonts or official Delphi product logos alongside this mark in a way that suggests a product bundle.

## Clear space

Keep padding around the badge at least **1/4 of the mark’s width** (e.g. ~32 px clear space on a 128 px square canvas). Do not crowd badges, buttons, or text against the curved corners.

## Minimum size

- **Favicon / IDE:** readable at **16×16** when exported to ICO; prefer **32×32** or larger for clarity.
- **README / docs:** **128–200 px** wide for the SVG or equivalent raster is typical.

## Correct use

- Scale **uniformly** (preserve aspect ratio).
- Place on **solid or subtly patterned** backgrounds with enough contrast (use [`logo-dark.svg`](logo-dark.svg) on dark pages).
- Prefer **SVG** for web; use **PNG** only where required (some social crawlers, legacy tools).

## Incorrect use

- Do not **stretch** or **skew** the badge.
- Do not **change hue** arbitrarily (keep palette cohesive with the table above or update this doc when rebranding).
- Do not **outline** with clashing neon colors for “effect.”
- Do not **crop** the rounded square into a harsh rectangle that removes the corner radius entirely.
- Do not **add** third-party logos *inside* the badge.

## Wordmark

“CryptoLib4Pascal” in plain text beside or below the mark is sufficient; no official custom logotype is required.
