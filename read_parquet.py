import pandas as pd
  
DOMAINS_FILE = "domains.parquet"

def load_domains(parquet_path=DOMAINS_FILE):
    """Citește domeniile din fișierul Parquet."""
    df = pd.read_parquet(parquet_path)
    # căutăm o coloană cu „domain” în nume; altfel o luăm pe prima
    column = next((c for c in df.columns if "domain" in c.lower()), df.columns[0])
    domains = df[column].dropna().astype(str).str.strip().str.lower().tolist()
    print(f"Loaded {len(domains)} domains from column '{column}'")
    return domains

if __name__ == "__main__":
    domains = load_domains()
    print(f"{len(domains)} domains")
    print(domains[:5])