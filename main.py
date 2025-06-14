from extraction_CVE import extract_cve_from_local
from enrichissement import enrich_all_offline
from consolidation import build_dataframe
import pandas as pd


if __name__ == "__main__":
    cve_infos = extract_cve_from_local()
    print(f"{len(cve_infos)} CVE extraites depuis les bulletins.")

    enriched_data = enrich_all_offline(cve_infos)
    print(f"{len(enriched_data)} CVE enrichies.")

    df = build_dataframe(enriched_data)
    df.to_csv("data/cve_enriched_data.csv", index=False)
    print("CSV généré avec", len(df), "lignes.")
