# SSH Brute Force Attack Scanner
# Een log bestand scanner die controleert hoeveel (gefaalde) inlogpogingen gedaan worden binnen een bepaalde tijd
# Gemaakt door: Mitchell van der Kolk, studentnummer: 500861728, april 2023

# Om het script te runnen, voer het volgende in de terminal:
# python3 BruteForceLogScanner.py bestand.log

# Imports van bibliotheken die gebruikt worden voor de 'SSH Brute Force Attack Scanner'
import csv
import sys
from datetime import datetime, timedelta
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Stel de bestandsnamen in 
log = sys.argv[1]
csv_file = "events.csv"

# Open het logbestand en lees de inhoud
file = open(log, "r")

# Initialiseer dictionaries om de aantallen van gebeurtenissen bij te houden
event_counts = {"started": 0, "finished": 0, "failed": 0}
brute_force_counts = {"bruteforce": 0}

# Definieer de event codes voor elke gebeurtenis
event_codes = {"started": 100, "finished": 200, "failed": 300, "bruteforce": 301}

# Initialiseer variabelen om het totale aantal gebeurtenissen bij te houden
total_count = 0

# Maak een lege lijst om brute force aanvallen bij te houden
bruteforce = []

# Initialiseer dictionaries om het aantal mislukte loginpogingen 
failed_login_counts = {}

# en het tijdstip van de laatste mislukte loginpoging bij te houden, 
last_failed_login_time = {}

# evenals een sessiedictionary
session_dict = {}

# Open het CSV-bestand om gegevens weg te schrijven
with open(csv_file, "w", newline='') as f:
    writer = csv.writer(f)

    # Schrijf de kolomkoppen
    writer.writerow(["Timestamp", "PID", "Logon User", "IP Address", "Status", "Event Code"])

    # Lees elke lijn in het logboek en split deze
    for line in file:
        stripped = line.split(';')
        timestamp = datetime.strptime(stripped[0], '%Y-%m-%d %H:%M:%S.%f')
        proces_id = stripped[2]
        log_event = stripped[3]
        
        # Bepaal de status van de gebeurtenis (gestart, voltooid, mislukt, bruteforce)
        status = log_event.split()[-1]
        event_counts[status] += 1
        total_count += 1

        # Haal de logingegevens op
        logon_user = log_event.split()[1]
        ip_addr = log_event.split()[-2]

        # Als de inlogpoging is mislukt
        if status == "failed":
            # Controleer of er al een eerdere mislukte inlogpoging was vanaf hetzelfde IP-adres binnen de afgelopen 10 seconden
            if ip_addr in failed_login_counts and last_failed_login_time[ip_addr] >= timestamp - timedelta(seconds=10):
                failed_login_counts[ip_addr] += 1
                # Als er meer dan 2 mislukte inlogpogingen waren binnen de afgelopen 10 seconden, voeg dan het IP-adres toe aan de lijst met brute-force aanvallen
                if failed_login_counts[ip_addr] >= 2:
                    bruteforce.append([str(timestamp), ip_addr])
                    brute_force_counts["bruteforce"] += 1
                    # Schrijf de gebeurtenis weg in het CSV-bestand
                    writer.writerow([timestamp, proces_id, logon_user, ip_addr, status, event_codes["bruteforce"]])
            # Als er geen eerdere mislukte inlogpoging was vanaf hetzelfde IP-adres binnen de afgelopen 10 seconden, registreer dan de huidige mislukte inlogpoging
            else:
                failed_login_counts[ip_addr] = 1
                last_failed_login_time[ip_addr] = timestamp
                # Schrijf de gebeurtenis weg in het CSV-bestand
                writer.writerow([timestamp, proces_id, logon_user, ip_addr, status, event_codes[status]])
        # Als de inlogpoging slaagt, schrijf de gebeurtenis weg in het CSV-bestand
        else:
            writer.writerow([timestamp, proces_id, logon_user, ip_addr, status, event_codes[status]])

# Sluit het logboekbestand
file.close()

# Print belangrijke output
print("Log analysis complete!")

for event_type, count in event_counts.items():
    print(f"{event_type} events: {count} ({event_codes[event_type]})")

for line, count2 in brute_force_counts.items():
    print(f"Bruteforce total:", count2)

for line in bruteforce:
    print(", ".join(line))

# Laad de data van het CSV bestand in een dataframe
data = pd.read_csv('events.csv')

# Plot het aantal login pogingen per gebruiker
login_attempts = data[data['Event Code'] == 300]
sns.countplot(x='Logon User', data=login_attempts)
plt.xlabel('Totaal aantal mislukte logins per gebruiker')
plt.ylabel('Totaal aantal mislukte logins')
plt.xticks(rotation=90)
plt.show()

# Plot het aantal login pogingen per IP-adres
login_attempts = data[data['Event Code'] == 300]
sns.countplot(x='IP Address', data=login_attempts)
plt.xlabel('Totaal aantal mislukte logins per IP-adres')
plt.ylabel('Totaal aantal mislukte logins')
plt.xticks(rotation=90)
plt.show()

# Converteer de kolom 'Timestamp' naar het datetime-formaat en stel deze in als index
data['Timestamp'] = pd.to_datetime(data['Timestamp'])
data.set_index('Timestamp', inplace=True)

# Resample de data naar een uurlijkse frequentie voor elke gebruiker
for user in data['Logon User'].unique():
    failed_logins = data[(data['Event Code'] == 300) & (data['Logon User'] == user)]
    failed_logins_per_hour = failed_logins.resample('H').size()

    # Formatteer de index als string in het gewenste tijdformaat
    hours = failed_logins_per_hour.index.hour
    hour_labels = [f"{hour:02d}:00" for hour in hours]
    dates = failed_logins_per_hour.index.strftime('%Y-%m-%d')
    date_labels = [date if hour == 0 else '' for hour, date in zip(hours, dates)]

    # Plot de data
    plt.plot(failed_logins_per_hour.index, failed_logins_per_hour, label=user)

plt.xlabel('Date and Hour')
plt.ylabel('Failed Login Attempts')
plt.xticks(rotation=90)
plt.legend()
plt.show()

# Einde script 




