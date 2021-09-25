import pandas as pd
from opendp.smartnoise.sql import PandasReader, PrivateReader
from opendp.smartnoise.metadata import CollectionMetadata
pums = pd.read_csv('data/PUMS.csv')
meta = CollectionMetadata.from_file('data/PUMS.yaml')
query = 'SELECT married, COUNT(pid) AS n FROM PUMS.PUMS GROUP BY married'
reader = PandasReader(pums, meta)
result = reader.execute(query) 
print("True data:            " + str(result)) #真实数据
private_reader = PrivateReader(reader, meta, 4.0) #epsilon越大，隐私保护越弱
result_dp = private_reader.execute(query)
print("DP data(epsilon=4.0): " + str(result_dp))
private_reader = PrivateReader(reader, meta, 0.2) #epsilon越小，隐私保护越强
result_dp = private_reader.execute(query)
print("DP data(epsilon=0.2): " + str(result_dp))