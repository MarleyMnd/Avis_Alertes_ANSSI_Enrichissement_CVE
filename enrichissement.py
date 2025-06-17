import requests
import time
import os
import json


def enrichissement_api_cve():
    cve_id = "CVE-2023-24488"
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)
    data = response.json()

    # Extraire la description
    description = data["containers"]["cna"]["descriptions"][0]["value"]

    # Extraire le score CVSS
    #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
    #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
    cvss_score = data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
    cwe = "Non disponible"
    cwe_desc = "Non disponible"
    problemtype = data["containers"]["cna"].get("problemTypes", {})
    if problemtype and "descriptions" in problemtype[0]:
        cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
        cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible")

    # Extraire les produits affectés
    affected = data["containers"]["cna"]["affected"]
    for product in affected:
        vendor = product["vendor"]
        product_name = product["product"]
        versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
        print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")

    # Afficher les résultats
    print(f"CVE : {cve_id}")
    print(f"Description : {description}")
    print(f"Score CVSS : {cvss_score}")
    print(f"Type CWE : {cwe}")
    print(f"CWE Description : {cwe_desc}")


def enrichissement_api_epss():
    # URL de l'API EPSS pour récupérer la probabilité d'exploitation
    cve_id = "CVE-2023-46805"
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    # Requête GET pour récupérer les données JSON
    response = requests.get(url)
    data = response.json()
    # Extraire le score EPSS
    epss_data = data.get("data", [])
    if epss_data:
        epss_score = epss_data[0]["epss"]
        print(f"CVE : {cve_id}")
        print(f"Score EPSS : {epss_score}")
    else:
        print(f"Aucun score EPSS trouvé pour {cve_id}")


def enrich_cve_data(cve_id):
    enriched = {
        "cve_id": cve_id,
        "description": "Non disponible",
        "cvss_score": None,
        "base_severity": "Non disponible",
        "cwe_id": "Non disponible",
        "cwe_desc": "Non disponible",
        "epss_score": None,
        "vendors": [],
    }

    # API MITRE
    try:
        url_mitre = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        response = requests.get(url_mitre)
        data = response.json()

        enriched["description"] = data["containers"]["cna"]["descriptions"][0]["value"]

        metrics = data["containers"]["cna"].get("metrics", [])
        if metrics:
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

        affected = data["containers"]["cna"].get("affected", [])
        for product in affected:
            vendor = product.get("vendor", "")
            product_name = product.get("product", "")
            versions = [v["version"] for v in product.get("versions", []) if v.get("status") == "affected"]
            enriched["vendors"].append({"vendor": vendor, "product": product_name, "versions": versions})

    except Exception as e:
        print(f"[Erreur MITRE] {cve_id}: {e}")

    # API EPSS
    try:
        url_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        response = requests.get(url_epss)
        epss_data = response.json().get("data", [])
        if epss_data:
            enriched["epss_score"] = epss_data[0]["epss"]
    except Exception as e:
        print(f"[Erreur EPSS] {cve_id}: {e}")

    time.sleep(0.1) # rate limit
    return enriched


def enrich_all(cve_list):
    all_data = []
    total = len(cve_list)
    for i, cve_id in enumerate(cve_list, start=1):
        print(f"[{i}/{total}] Enrichissement de {cve_id}...")
        data = enrich_cve_data(cve_id)
        all_data.append(data)
    return all_data


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
