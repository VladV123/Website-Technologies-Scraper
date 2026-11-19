import pandas as pd

df = pd.read_parquet("domains.parquet")   

print(df.head())      
print(df.columns)     
print(len(df))