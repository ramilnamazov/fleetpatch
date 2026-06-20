# Website Audit — ramilography.com

_Reviewed 2026-06-20. Site is on Git + Vercel, which means I can make these
changes as code once the repo is added to my workspace (see note at bottom)._

## What's working
- **Strong, distinctive brand voice:** "Sculpting with light. Defining with
  shadow." Premium, memorable, justifies higher pricing.
- **Clean navigation** and a visible **"Book a Session"** CTA in the nav.
- Clear, focused structure (Portfolio / Contact / Book a Session).

## What's costing you bookings (prioritized)

### 🔴 High impact — do first
1. **No clear "what I shoot."** A visitor can't tell in 5 seconds whether you do
   their thing (family? real estate? product?). → Add the 3 service pages from
   `strategy.md` with their own galleries and CTAs.
2. **No location anywhere.** Google can't rank you locally and humans can't tell
   you serve them. → Put "New Jersey & NYC" in the homepage, footer, page
   titles, and meta descriptions. Critical for "[city] photographer" searches.
3. **No social proof.** Zero testimonials/reviews on the page. → Add 3–5 client
   quotes and wire up a Google review link. Trust = bookings.
4. **No pricing signal.** Not even a "from $X." People who see no price assume
   "too expensive" or bounce to someone who shows one. → Add "investment starts
   at…" per service (no need to publish full price lists).

### 🟡 Medium impact
5. **Confirm the contact form actually works** and emails you instantly, with an
   auto-reply so no lead goes cold. (Response speed beats everything in this
   business.)
6. **No portfolio preview on the homepage** — make people click to see work.
   Add a few hero images per niche above the fold.
7. **No tracking** (couldn't detect analytics/pixel). → Install GA4 + Meta Pixel
   now, so when we run ads later they actually work and we can measure inquiries.
8. **No About/credibility** — a face, a story, and "why me" build trust fast.

### 🟢 Polish / later
9. Email capture (lead magnet: "NJ mini-session dates" or "brand shoot guide").
10. SEO basics: page titles, meta descriptions, image alt text, sitemap, fast
    mobile load (Vercel helps here already).
11. Schema markup (LocalBusiness / Photograph) for richer Google results.

## Suggested page structure
```
/                home — brand hero + niche tiles + featured work + proof + CTA
/portraits       families/portraits — gallery, who it's for, from-$, inquire
/branding        brand/product/food — gallery, ROI angle, from-$, inquire
/real-estate     listings/interiors — gallery, fast-turnaround, from-$, inquire
/portfolio       full showcase (exists)
/about           you, your story, your approach, your face
/contact         working form + fast auto-reply (exists, verify it works)
```

## Note on me doing this as your developer
Your site lives in a Git repo connected to Vercel. The repo I'm currently
connected to is `ramilnamazov/fleetpatch` (a different project). To have me edit
the real website code, the **ramilography site repo needs to be added to this
session's scope**. Tell me the repo name (e.g. `ramilnamazov/ramilography`) and
I'll request it be added; then I can make every fix above as real PRs you review
and Vercel auto-deploys.
