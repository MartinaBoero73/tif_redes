import pandas as pd

# Cargar el archivo CSV
df = pd.read_csv('simulacion_paquetesTCP_Hping3.csv')

# Mostrar las primeras filas del dataframe para entender su estructura
print(df.head())

# Análisis de las características de los paquetes
# Puedes ajustar los nombres de las columnas según tu archivo CSV
# Aquí asumimos que el CSV tiene columnas como 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'ip.ttl', etc.

# Ejemplo: Agrupar por direcciones IP de origen y calcular estadísticas básicas
ip_stats = df.groupby('Source').agg({
    'Length': ['mean', 'std'],  # Usar la columna 'Length' para el tamaño del paquete
    'No.': 'nunique',           # Usar la columna 'No.' para el identificador único
    'Time': ['mean', 'std']     # Usar la columna 'Time' para el tiempo
}).reset_index()

print(ip_stats)

# Identificación de patrones únicos para fingerprinting
# Por ejemplo, dispositivos móviles pueden tener TTL específico y puertos fuente/destino característicos
mobile_devices = ip_stats[(ip_stats[('Length', 'mean')] < 64) & 
                          (ip_stats[('No.', 'nunique')] > 1000)]

print("Posibles dispositivos móviles:")
print(mobile_devices)

# Puedes seguir refinando las reglas para identificar otros tipos de dispositivos
