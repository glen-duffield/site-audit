# Site audit dashboard

Automated weekly audit of public-facing website hygiene across multiple product domains. Runs in GitHub Actions, results published to GitHub Pages.

## What it checks

27 checks per domain plus stack + tracking detection:

- **Discoverability** — HTTPS, robots.txt, sitemap.xml, canonical, custom 404, apex/www consistency, HTTP→HTTPS redirect, meta robots
- **On-page SEO** — title, meta description, single H1, heading hierarchy, alt text, HTML lang, placeholder text
- **Social sharing** — OpenGraph tags, og:image, Twitter card, LinkedIn preview
- **Structured data** — JSON-LD presence + validity
- **Performance + trust** — page weight, mobile viewport, favicon (incl. apple-touch-icon, manifest, theme-color), security headers, email DNS (SPF + DMARC)
- **Tracking** — LinkedIn Insight Tag (incl. detection inside GTM containers)
- **Stack detection** — framework, CSS, hosting/CDN, CMS, registrar
- **Tracking installations** — GA4, GTM, Search Console, PostHog, LinkedIn Insight, Meta Pixel
- **Health over time** — sparkline trends from rolling history

## How it runs

GitHub Actions runs `marketing-audit.py` every Sunday at 21:00 UTC (Monday morning NZ time). Results are committed back to the repo and GitHub Pages serves the dashboard.

To trigger a run manually: **Actions** tab → **Site audit** → **Run workflow**.

## Configure

Edit `audit-config.json` to add/remove brands or domains, or to add manual overrides for false-positive findings.

```json
{
  "brands": [
    {
      "name": "Example",
      "tagline": "What we do",
      "domains": ["example.com"]
    }
  ],
  "overrides": {
    "example.com": {
      "5_404": "Branded 404 verified manually"
    }
  }
}
```

## Files

- `marketing-audit.py` — the audit script (Python stdlib only, no dependencies)
- `audit-config.json` — brands, domains, overrides
- `audit-dashboard-template.html` — dashboard HTML template
- `marketing-audit-data.json` — latest audit results (auto-updated)
- `audit-history.json` — rolling history for sparklines (auto-updated)
- `marketing-audit-dashboard.html` / `index.html` — baked dashboard with all data inlined
- `.github/workflows/audit.yml` — schedule + run config
