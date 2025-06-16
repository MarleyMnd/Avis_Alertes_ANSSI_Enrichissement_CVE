import os
import json


def enrich_cve_data_offline(cve_id, mitre_dir="mitre", first_dir="first"):
    enriched = {
        "cve_id": cve_id,
        "description": "Non disponible",
        "cvss_score": None,
        "base_severity": "Non disponible",
        "cwe_id": "Non disponible",
        "cwe_desc": "Non disponible",
        "epss_score": None,
        "vendors": []
    }

    # Fichier local MITRE
    mitre_path = os.path.join(mitre_dir, f"{cve_id}.json")
    if os.path.exists(mitre_path):
        with open(mitre_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                enriched["description"] = data["containers"]["cna"]["descriptions"][0]["value"]

                metrics = data["containers"]["cna"].get("metrics", [])
                for metric in metrics:
                    if "cvssV3_1" in metric:
                        enriched["cvss_score"] = metric["cvssV3_1"]["baseScore"]
                        enriched["base_severity"] = metric["cvssV3_1"]["baseSeverity"]
                        break
                    elif "cvssV3_0" in metric:
                        enriched["cvss_score"] = metric["cvssV3_0"]["baseScore"]
                        enriched["base_severity"] = metric["cvssV3_0"]["baseSeverity"]
                        break

                problemtype = data["containers"]["cna"].get("problemTypes", [])
                if problemtype and "descriptions" in problemtype[0]:
                    enriched["cwe_id"] = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                    enriched["cwe_desc"] = problemtype[0]["descriptions"][0].get("description", "Non disponible")

                for product in data["containers"]["cna"].get("affected", []):
                    vendor = product.get("vendor", "")
                    product_name = product.get("product", "")
                    versions = [v["version"] for v in product.get("versions", []) if v.get("status") == "affected"]
                    enriched["vendors"].append({
                        "vendor": vendor,
                        "product": product_name,
                        "versions": versions
                    })
            except Exception as e:
                print(f"Erreur JSON MITRE pour {cve_id}: {e}")

    # Fichier local EPSS
    first_path = os.path.join(first_dir, f"{cve_id}.json")
    if os.path.exists(first_path):
        try:
            with open(first_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                epss_data = data.get("data", [])
                if epss_data:
                    enriched["epss_score"] = epss_data[0]["epss"]
        except Exception as e:
            print(f"Erreur JSON EPSS pour {cve_id}: {e}")

    return enriched


def enrich_all_offline(cve_infos, mitre_dir="data_pour_TD_final/mitre", first_dir="data_pour_TD_final/first"):
    all_data = []
    total = len(cve_infos)
    for idx, info in enumerate(cve_infos, 1):
        print(f"[{idx}/{total}] Enrichissement local de {info['cve_id']}...")
        enriched = enrich_cve_data_offline(info["cve_id"], mitre_dir, first_dir)
        enriched.update({
            "id_anssi": info.get("id_anssi"),
            "title": info.get("title"),
            "published": info.get("published"),
            "type": info.get("type"),
            "link": info.get("link")
        })
        all_data.append(enriched)
    return all_data
