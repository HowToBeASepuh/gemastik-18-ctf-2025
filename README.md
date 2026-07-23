# GEMASTIK XVIII CTF 2025 — HowToBeASepuh Write-Ups

English write-ups for the **Cyber Security (CTF) division of GEMASTIK 18**, Indonesia's national
ICT competition for university students, by team **HowToBeASepuh** (Institut Teknologi Bandung).
Built as a static site with [Eleventy (11ty)](https://www.11ty.dev/). The event has two rounds —
**Qualifications** and **Finals** — reflected in the challenge index.

## Challenges

| Round | Category | Challenge |
|-------|----------|-----------|
| Quals | Rev | Scripts |
| Quals | Web | none |
| Final | Web | Blogpost, cdn |
| Final | Crypto | Phew |

## Local development

```bash
npm install
npm start        # dev server at http://localhost:8080
npm run build    # build static site into _site/
```

## Project layout

```
description.txt          Competition blurb (source of truth, shown on the home page)
.source/                 Original challenge files + source PDF write-ups (Quals + Final; archival)
eleventy.config.js       Eleventy config (ESM); collection ordered by round → category → points
src/
  _data/site.js          Site metadata; reads description.txt, English descriptionEn
  _data/authors.js       Team-member author registry (avatar + GitHub)
  _includes/             base.njk (shell) + challenge.njk (write-up layout)
  assets/                style.css, prism.css, theme.js
  index.njk              Landing page: challenge index grouped by round → category
  writeups/quals/<cat>/  Qualifications write-ups (front-matter: part: Quals)
  writeups/final/<cat>/  Finals write-ups (front-matter: part: Final)
  files/<round>/<chall>/ Downloadable challenge attachments
  img/<chall>/           Figures extracted from the PDF write-ups
```
