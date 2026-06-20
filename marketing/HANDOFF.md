# Project Handoff — Ramilography Marketing System

_Use this to continue in a new session started on the correct repo
(`ramilography`, or a new `ramilography-marketing` repo). Paste the summary
section into the new chat so it can pick up with full context._

---

## Who & what
- **Client:** Ramil (ramil.namazov@gmail.com), photography side hustle.
- **Website:** ramilography.com (Next.js-style site on Git + Vercel).
  - Vercel preview seen: ramilography-svqx2v7ssv-9828s-projects.vercel.app
  - Website repo: `ramilnamazov/ramilography` (NOT yet connected to a session).
- **Goal:** Build a full marketing + ops system so one person + an AI agency can
  run ads, website, content, automated posting, and lead follow-up.
- **Role split:** Ramil = photographer + approver. AI = strategy, production, dev, ops.

## Locked decisions
- **Primary goal:** All of it — bookings (first priority), audience, email list,
  products (later). Sequence: bookings → audience/list as byproduct → products.
- **Niches:** Everything EXCEPT weddings. Target money-makers: portraits/family,
  branding/product/food, real estate/spaces. **Sports stays** as a core offer.
- **Budget:** Organic first; start paid ads later based on results.
- **Market:** New Jersey primary; NYC reachable; will travel if worth it or if
  client pays a travel fee; national is opportunistic/inbound.
- **Brand:** Keep the premium, cinematic positioning — "Sculpting with light.
  Defining with shadow." Umbrella art brand + dedicated service pages underneath.

## Business facts gathered
- **Live pricing (from /book):** Consultation free (15 min); Portraits from $200;
  Couples from $250; Family from $275; Events from $300; Sports from $275.
  $50 non-refundable deposit; balance at session. Contact = Instagram DM only.
- **Pricing is variable** by hours booked and number of edited photos; "from $X"
  is the entry point.

## Website audit (key findings)
Strong brand + clean nav + visible "Book a Session" CTA. But losing bookings:
1. Can't tell WHAT he shoots in 5 seconds (no service clarity).
2. No location stated anywhere → bad for "NJ/NYC photographer" local SEO.
3. No testimonials/reviews → no trust signal.
4. No package inclusions (duration, # edited photos, turnaround).
5. Contact only via Instagram DM → slow/leaky; needs a real inquiry form + auto-reply.
6. No analytics/Meta Pixel detected → future ads would be blind.
7. Missing service pages for branding/product/food and real estate (his money-makers).

## Recommended site structure
`/` (brand hero + niche tiles + featured work + proof + CTA), `/portraits`,
`/branding`, `/real-estate`, `/portfolio`, `/about`, `/contact` (working form).
Each service page: own headline, gallery, "who it's for," "from $X," inquiry CTA.

## Roadmap (phases)
0. Foundation (brand/strategy, claim+optimize Google Business Profile)
1. Convert (website fixes, GA4 + Search Console + Meta Pixel, fast inquiry replies, local SEO)
2. Content engine (pillars, monthly calendar, automated scheduling via free Meta Business Suite)
3. Paid ads (start with retargeting + local lead ads, once funnel converts)
4. Follow-up & retention (reviews, referrals, light email list, reactivation)
5. Measure monthly (inquiries, bookings, revenue, spend → do more/less)

## Files produced (in fleetpatch:marketing/ — recreate in new repo)
- `README.md` — system overview + diagram
- `00-intake-brand-brief.md` — fill-in intake form (still mostly blank)
- `01-access-checklist.md` — accounts/access needed + safe-sharing steps
- `strategy.md` — locked decisions + positioning per niche
- `website-audit.md` — prioritized fix list
- `offers-pricing.md` — live pricing + gaps + variable-pricing decision
- `roadmap.md` — phased plan

## OPEN QUESTIONS / still needed from Ramil
1. **Add-on rate sheet numbers:** extra hour = $?, extra ~10 edited photos = $?,
   # edited photos in a base session = ?
2. **Approve drafting Branding/Content and Real Estate packages?** (his two
   missing money-makers).
3. **Photos** sorted by niche (5–8 each) for service-page galleries.
4. **Testimonials/reviews** (screenshots fine).
5. **Google Business Profile** — add AI as Manager (highest free ROI; not yet done).
6. **Fill in the brand brief** (pricing, about-me, ideal client).
7. **Connect the website repo** to a session so fixes ship as PRs (Vercel auto-deploys).

## Immediate next actions once in the correct repo
- Move/recreate these `marketing/` files into the new repo.
- Start Phase 1 website fixes as PRs: add location + service pages + package
  inclusions + inquiry form + GA4/Pixel.
- Optimize Google Business Profile in parallel (free, high impact).
