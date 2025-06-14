import requests
import re
import os
import json


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
