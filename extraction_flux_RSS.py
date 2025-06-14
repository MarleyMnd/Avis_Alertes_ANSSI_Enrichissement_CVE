import feedparser

def extract_flux_rss():
    urls = []
    for flux_type in ["avis", "alerte"]:
        url = f"https://www.cert.ssi.gouv.fr/{flux_type}/feed"
        rss_feed = feedparser.parse(url)
        for entry in rss_feed.entries:
            urls.append({
                "id": entry.id.split("/")[-2],
                "title": entry.title,
                "link": entry.link,
                "published": entry.published,
                "type": flux_type.capitalize()
            })
    return urls
