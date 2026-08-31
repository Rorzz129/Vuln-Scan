from __future__ import annotations

from typing import Any
import re

ALIASES = {
    "apache": "Apache httpd",
    "apache http server": "Apache httpd",
    "apache httpd": "Apache httpd",
    "httpd": "Apache httpd",
    "nginx": "nginx",
    "openresty": "OpenResty",
    "microsoft iis": "Microsoft IIS",
    "microsoft-iis": "Microsoft IIS",
    "iis": "Microsoft IIS",
    "prestashop": "PrestaShop",
    "wordpress": "WordPress",
    "woocommerce": "WooCommerce",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "php": "PHP",
    "angular": "Angular",
    "angularjs": "AngularJS",
    "react": "React",
    "reactjs": "React",
    "vue": "Vue.js",
    "vuejs": "Vue.js",
    "vue.js": "Vue.js",
    "nextjs": "Next.js",
    "next.js": "Next.js",
    "nuxt": "Nuxt",
    "nuxt.js": "Nuxt",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "express": "Express",
    "laravel": "Laravel",
    "django": "Django",
    "ruby on rails": "Ruby on Rails",
    "rails": "Ruby on Rails",
    "apache tomcat": "Apache Tomcat",
    "tomcat": "Apache Tomcat",
    "cloudflare": "Cloudflare",
    "heroku": "Heroku",
    "caddy": "Caddy",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "postgres": "PostgreSQL",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "openssh": "OpenSSH",
}

def normalize_name(value: Any) -> str:
    text = str(value or "").strip().casefold()
    text = re.sub(r"[_:/+.-]+", " ", text)
    return " ".join(text.split())

def canonical_name(value: Any) -> str:
    raw = str(value or "").strip()
    normalized = normalize_name(raw)

    if normalized in ALIASES:
        return ALIASES[normalized]

    for alias, canonical in ALIASES.items():
        if normalized == alias or normalized.startswith(alias + " "):
            return canonical

    return raw

def known_aliases(value: Any) -> list[str]:
    canonical = canonical_name(value)
    result = []

    for alias, target in ALIASES.items():
        if target == canonical and alias != normalize_name(canonical):
            result.append(alias)

    return sorted(set(result))
