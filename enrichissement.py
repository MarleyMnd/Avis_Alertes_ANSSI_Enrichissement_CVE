import requests
import time
import json

def enrich_cve_data(cve_list):
    enriched_data = []
    
    for cve_item in cve_list:
        cve_id = cve_item.get("cve_id")
        if not cve_id:
            continue
            
        print(f"Enriching {cve_id}...")
        
        # Initialize with base data
        enriched_item = cve_item.copy()
        
        # Default values
        enriched_item.update({
            "description": "Not available",
            "cvss_score": 0.0,
            "base_severity": "UNKNOWN",
            "cwe_id": "Unknown",
            "cwe_desc": "Unknown",
            "epss_score": 0.0,
            "vendors": []
        })
        
        # Get MITRE data
        mitre_data = get_mitre_data(cve_id)
        if mitre_data:
            enriched_item.update(mitre_data)
            
        # Get EPSS score
        epss_data = get_epss_data(cve_id)
        if epss_data:
            enriched_item["epss_score"] = epss_data
            
        enriched_data.append(enriched_item)
        
        # Avoid rate limiting
        time.sleep(1)
        
    return enriched_data

def get_mitre_data(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    try:
        response = requests.get(url, headers={
            "User-Agent": "CVE-Enrichment-Tool/1.0"
        })
        
        if response.status_code != 200:
            print(f"Error fetching MITRE data for {cve_id}: {response.status_code}")
            return None
            
        data = response.json()
        
        if not data.get("vulnerabilities") or len(data["vulnerabilities"]) == 0:
            return None
            
        vuln = data["vulnerabilities"][0]["cve"]
        
        # Extract description
        description = "Not available"
        if vuln.get("descriptions"):
            for desc in vuln["descriptions"]:
                if desc.get("lang") == "en":
                    description = desc.get("value", "Not available")
                    break
        
        # Extract CVSS data
        cvss_score = 0.0
        base_severity = "UNKNOWN"
        if vuln.get("metrics", {}).get("cvssMetricV31"):
            cvss_data = vuln["metrics"]["cvssMetricV31"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", 0.0)
            base_severity = cvss_data.get("baseSeverity", "UNKNOWN")
        elif vuln.get("metrics", {}).get("cvssMetricV30"):
            cvss_data = vuln["metrics"]["cvssMetricV30"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", 0.0)
            base_severity = cvss_data.get("baseSeverity", "UNKNOWN")
        elif vuln.get("metrics", {}).get("cvssMetricV2"):
            cvss_data = vuln["metrics"]["cvssMetricV2"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", 0.0)
            base_severity = cvss_data.get("baseSeverity", "UNKNOWN")
        
        # Extract CWE information
        cwe_id = "Unknown"
        cwe_desc = "Unknown"
        if vuln.get("weaknesses"):
            for weakness in vuln["weaknesses"]:
                if weakness.get("description"):
                    for desc in weakness["description"]:
                        if desc.get("lang") == "en" and desc.get("value"):
                            cwe_id = desc.get("value", "Unknown")
                            cwe_desc = cwe_id  # Using ID as description for now
                            break
        
        # Extract vendor and product information
        vendors = []
        if vuln.get("configurations"):
            for config in vuln["configurations"]:
                if config.get("nodes"):
                    for node in config["nodes"]:
                        if node.get("cpeMatch"):
                            for cpe in node["cpeMatch"]:
                                cpe_parts = cpe.get("criteria", "").split(":")
                                if len(cpe_parts) >= 5:
                                    vendor = cpe_parts[3]
                                    product = cpe_parts[4]
                                    version = cpe_parts[5] if len(cpe_parts) > 5 else "All"
                                    
                                    # Check if vendor already exists
                                    vendor_exists = False
                                    for v in vendors:
                                        if v["vendor"] == vendor and v["product"] == product:
                                            if version not in v["versions"]:
                                                v["versions"].append(version)
                                            vendor_exists = True
                                            break
                                    
                                    if not vendor_exists:
                                        vendors.append({
                                            "vendor": vendor,
                                            "product": product,
                                            "versions": [version]
                                        })
        
        return {
            "description": description,
            "cvss_score": cvss_score,
            "base_severity": base_severity,
            "cwe_id": cwe_id,
            "cwe_desc": cwe_desc,
            "vendors": vendors
        }
        
    except Exception as e:
        print(f"Error processing MITRE data for {cve_id}: {e}")
        return None

def get_epss_data(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    
    try:
        response = requests.get(url)
        
        if response.status_code != 200:
            print(f"Error fetching EPSS data for {cve_id}: {response.status_code}")
            return 0.0
            
        data = response.json()
        
        if not data.get("data") or len(data["data"]) == 0:
            return 0.0
            
        return float(data["data"][0].get("epss", 0.0))
        
    except Exception as e:
        print(f"Error processing EPSS data for {cve_id}: {e}")
        return 0.0