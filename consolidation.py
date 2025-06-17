import pandas as pd

def build_dataframe(enriched_data):
    print(f"Traitement de {len(enriched_data)} objets enrichis...")
    rows = []
    print(enriched_data[0])
    for item in enriched_data:
        base_row = {
            "ID ANSSI": item.get("id_anssi"),
            "Titre ANSSI": item.get("title"),
            "Type": item.get("type"),
            "Date de publication": item.get("published"),
            "Lien ANSSI": item.get("link"),
            "CVE": item["cve_id"],
            "Description": item["description"],
            "Score CVSS": item["cvss_score"],
            "Gravité CVSS": item["base_severity"],
            "Type CWE": item["cwe_id"],
            "CWE Description": item["cwe_desc"],
            "Score EPSS": item["epss_score"]
        }
        print("Ajout ligne pour CVE", item["cve_id"])
        if item["vendors"]:
            for v in item["vendors"]:
                row = base_row.copy()
                row.update({
                    "Éditeur": v["vendor"],
                    "Produit": v["product"],
                    "Versions affectées": ", ".join(v["versions"])
                })
                rows.append(row)
        else:
            row = base_row.copy()
            row.update({
                "Éditeur": "Non spécifié",
                "Produit": "Non spécifié",
                "Versions affectées": "Non spécifié"
            })
            rows.append(row)

    return pd.DataFrame(rows)

