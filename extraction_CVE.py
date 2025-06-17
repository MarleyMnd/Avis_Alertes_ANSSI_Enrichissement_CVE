import requests
import re
import os
import json
import csv
import pandas as pd


def extract_cve(bulletins):
    all_cve = []

    for bulletin in bulletins:
        json_url = bulletin["link"] + "json/"
        try:
            response = requests.get(json_url)
            if response.status_code != 200:
                continue
            data = response.json()

            # Récupération par clé
            cve_objs = data.get("cves", [])
            for cve in cve_objs:
                cve_id = cve.get("name")
                if cve_id:
                    all_cve.append({
                        "cve_id": cve_id,
                        "id_anssi": bulletin["id"],
                        "title": bulletin["title"],
                        "published": bulletin["published"],
                        "type": bulletin["type"],
                        "link": bulletin["link"]
                    })

        except Exception as e:
            print(f"[Erreur JSON] {json_url} : {e}")
            continue

    return all_cve


def extract_cve_from_local(dossier_avis="data_pour_TD_final/Avis", dossier_alertes="data_pour_TD_final/alertes"):
    all_cve = []

    for dossier, bulletin_type in [(dossier_avis, "Avis"), (dossier_alertes, "alerte")]:
        for fichier in os.listdir(dossier):
            path = os.path.join(dossier, fichier)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    cve_objs = data.get("cves", [])
                    for cve in cve_objs:
                        cve_id = cve.get("name")
                        if cve_id:
                            all_cve.append({
                                "cve_id": cve_id,
                                "id_anssi": data.get("id"),
                                "title": data.get("title"),
                                "published": data.get("publication", "Non spécifiée"),
                                "type": bulletin_type,
                                "link": data.get("url", f"https://www.cert.ssi.gouv.fr/{bulletin_type.lower()}/{data.get('id')}/")
                            })
            except Exception as e:
                print(f"Erreur lecture {path}: {e}")
    return all_cve


def extraire_info_communes(data):
    """Extrait les champs communs aux avis et alertes"""
    reference = data.get("reference", "")
    title = data.get("title", "")
    summary = data.get("summary", "").strip()
    cves = [cve.get("name") for cve in data.get("cves", [])]
    risks = [risk.get("description") for risk in data.get("risks", [])]

    # Produits affectés (description, nom produit, vendor)
    produits = []
    for item in data.get("affected_systems", []):
        produit = item.get("product", {})
        vendor = produit.get("vendor", {}).get("name", "")
        produits.append({
            "description": item.get("description", ""),
            "name": produit.get("name", ""),
            "vendor": vendor
        })

    # Solution = section content → extraire ## Solution
    content = data.get("content", "")
    solution = ""
    if "## Solution" in content:
        solution = content.split("## Solution", 1)[-1].strip()

    # Dates
    revisions = data.get("revisions", [])
    date_publication = (
        revisions[0].get("revision_date", "") if revisions else ""
    )
    nb_revisions = len(revisions)

    return {
        "reference": reference,
        "title": title,
        "summary": summary,
        "cves": ";".join(cves),
        "risks": ";".join(risks),
        "affected_products": json.dumps(produits, ensure_ascii=False),
        "solution": solution,
        "date_publication": date_publication,
        "nb_revisions": nb_revisions
    }


def traiter_fichier(filepath, type_doc):
    """Traite un fichier (alerte ou avis)"""
    try:
        with open(filepath, encoding='utf-8') as f:
            data = json.load(f)

        info = extraire_info_communes(data)
        info["type"] = type_doc
        info["date_cloture"] = data.get("closed_at", "") if type_doc == "alerte" else ""

        return info
    except Exception as e:
        print(f"Erreur dans {filepath}: {e}")
        return None


def parcourir_dossier(dossier, type_doc):
    """Parcourt tous les fichiers .txt d’un dossier donné"""
    resultats = []
    for nom_fichier in os.listdir(dossier):
        if nom_fichier.endswith(""):
            chemin = os.path.join(dossier, nom_fichier)
            info = traiter_fichier(chemin, type_doc)
            if info:
                resultats.append(info)
    return resultats


def fusionner_et_enregistrer(alertes, avis, chemin_sortie):
    """Fusionne les deux listes, aplatit les CVE, et écrit un CSV final sans colonne 'cves'"""
    lignes = alertes + avis

    colonnes = [
        "reference", "title", "summary", "cves", "cve",
        "risks", "affected_products", "solution",
        "date_publication", "date_cloture", "nb_revisions", "type"
    ]

    # Écrire les lignes aplaties avec 'cve'
    with open(chemin_sortie, "w", encoding="utf-8", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=colonnes)
        writer.writeheader()
        for ligne in lignes:
            cves = ligne.get("cves", "")
            if not cves:
                writer.writerow({**ligne, "cve": ""})
            else:
                for cve in cves.split(";"):
                    nouvelle_ligne = ligne.copy()
                    nouvelle_ligne["cve"] = cve.strip()
                    writer.writerow(nouvelle_ligne)

    # ✅ Supprimer la colonne 'cves' du fichier en la réécrivant sans cette colonne
    colonnes_sans_cves = [col for col in colonnes if col != "cves"]

    with open(chemin_sortie, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        lignes_sans_cves = [{k: ligne[k] for k in colonnes_sans_cves} for ligne in reader]

    with open(chemin_sortie, "w", encoding="utf-8", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=colonnes_sans_cves)
        writer.writeheader()
        writer.writerows(lignes_sans_cves)
