import os
import pandas as pd
from extraction_flux_RSS import extract_flux_rss
from extraction_CVE import extract_cve, extract_cve_from_local, parcourir_dossier, fusionner_et_enregistrer
from enrichissement import enrich_cve_data
from consolidation import build_dataframe

def main():
    # Extraction local
    folder_alertes = "data_pour_TD_final/alertes"
    folder_avis = "data_pour_TD_final/Avis"
    path_scrapped_data_csv = "data/cve_data_local.csv"

    alertes = parcourir_dossier(folder_alertes, "alerte")
    print(len(alertes))
    avis = parcourir_dossier(folder_avis, "avis")
    print(len(avis))

    fusionner_et_enregistrer(alertes, avis, path_scrapped_data_csv)
    print(f"Fichier CSV généré (local) : {path_scrapped_data_csv}")

    # Scrapping
    print("\nStarting CVE data extraction and enrichment process...")
    os.makedirs("data", exist_ok=True)

    print("Extracting data from RSS feeds...")
    bulletins = extract_flux_rss()
    print(f"Extracted {len(bulletins)} bulletins from RSS feeds")

    print("Extracting CVEs from bulletins...")
    cve_data = extract_cve(bulletins)
    print(f"Extracted {len(cve_data)} CVEs from online bulletins")

    try:
        print("Extracting CVEs from local files...")
        local_cve_data = extract_cve_from_local()
        print(f"Extracted {len(local_cve_data)} CVEs from local files")

        # Combine online and local CVE data
        all_cve_data = cve_data + local_cve_data

        # Remove duplicates based on cve_id
        unique_cve_ids = set()
        unique_cve_data = []

        for item in all_cve_data:
            if item["cve_id"] not in unique_cve_ids:
                unique_cve_ids.add(item["cve_id"])
                unique_cve_data.append(item)

        print(f"Total unique CVEs: {len(unique_cve_data)}")

    except Exception as e:
        print(f"Error extracting local CVEs: {e}")
        unique_cve_data = cve_data

    print("Enriching the first 15 CVEs...")
    cve_data_to_enrich = unique_cve_data[:5]
    enriched_data = enrich_cve_data(cve_data_to_enrich)
    print(f"Enriched {len(enriched_data)} CVEs")

    print("Building DataFrame...")
    df = build_dataframe(enriched_data)
    print(f"Created DataFrame with {len(df)} rows")

    output_file = "data/cve_enriched_data_scrapped.csv"
    print(f"Saving to {output_file}...")
    df.to_csv(output_file, index=False, encoding="utf-8")
    print(f"Data saved to {output_file}")

    print("Process completed successfully!")

if __name__ == "__main__":
    main()
