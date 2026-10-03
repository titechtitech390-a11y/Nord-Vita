

# NordVita – Security Incident Analysis

 > **Blue Team / SOC investigation project**\
>  Network Traffic Analysis • PCAP • FTP/HTTP • SQLite • Data Exposure • Encoding Analysis

 ## 📌 Incident Summary

 The project simulates an investigation of a security incident involving the fictional company **NordVita**.

 The investigation was performed using network traffic captured in a PCAP file, a SQLite database containing application and access logs, and a data sample recovered from an attacker-controlled server.

 The main objective was to reconstruct the incident, identify exposed information, determine the scope of the data access and document the findings in an incident report.

---

 ## 🛠️ Tools

 - **Linux**
- **TShark**
- **Wireshark**
- **SQLite**
- **CyberChef**
- **Git / GitHub**

---

 # 1\. Network Traffic Analysis

 ## Objective

 The first stage was the analysis of the captured network traffic stored in a PCAP file.

 The investigation focused on identifying:

 - suspicious HTTP requests,
- FTP authentication,
- files transferred using FTP,
- destination IP addresses,
- information transmitted without adequate protection.

---

 ## HTTP investigation

 I searched the PCAP for HTTP traffic involving the identified external IP address.

```
tshark -r materialy/z5_ruch_sieciowy/nordvita_capture.pcap \
-Y 'http && ip.addr==<IP>' \
-T fields \
-e frame.time_relative \
-e ip.src \
-e ip.dst \
-e http.request.method \
-e http.request.uri
```

 The analysis identified an HTTP `POST` request to:

```
/gate.php
```

 The full request was then inspected with:

```
tshark -r materialy/z5_ruch_sieciowy/nordvita_capture.pcap \
-Y 'http.request.method == POST && ip.dst == <IP>' \
-V
```

 The HTTP payload contained application data transmitted directly in the request body.

 This demonstrated that sensitive information was present in network traffic in a form that could be recovered from the packet capture.

---

 # 2\. FTP Investigation

 The next step was to investigate FTP authentication.

```
tshark -r materialy/z5_ruch_sieciowy/nordvita_capture.pcap \
-Y 'ftp.request.command == USER || ftp.request.command == PASS' \
-T fields \
-e frame.number \
-e ip.src \
-e ip.dst \
-e ftp.request.command \
-e ftp.request.arg
```

 This revealed FTP `USER` and `PASS` commands.

 The reason the password could be observed directly is that standard FTP authentication transmits credentials without encryption. Anyone capable of capturing the traffic can therefore potentially recover the credentials.

---

 ## File transfer

 I searched for the FTP `STOR` command:

```
tshark -r materialy/z5_ruch_sieciowy/nordvita_capture.pcap \
-Y 'ftp.request.command == STOR' \
-T fields \
-e frame.number \
-e ip.src \
-e ip.dst \
-e ftp.request.arg
```

 The captured traffic showed a file upload using the `STOR` command.

 The investigation therefore established that data was transferred from the internal host to the external destination using FTP.

---

 # 3\. Database Investigation

 The second source of evidence was the SQLite database.

 The database was opened with:

```
sqlite3 materialy/z6_baza/nordvita_crm.db
```

 Available tables:

```
.tables
```

 The database contained:

```
klienci
logi_dostepu
uzytkownicy
```

---

 ## Access logs

 The structure of the access log table was identified with:

```
.schema logi_dostepu
```

 Relevant fields included:

```
data_czas
login
akcja
tabela_docelowa
liczba_rekordow
ip_zrodlowe
```

 To identify activity associated with the external IP:

```
SELECT COUNT(*)
FROM logi_dostepu
WHERE ip_zrodlowe='<IP>';
```

 The detailed activity was then examined using:

```
SELECT data_czas, login, akcja,
       tabela_docelowa, liczba_rekordow
FROM logi_dostepu
WHERE ip_zrodlowe='<IP>';
```

 The logs showed multiple database operations, including an `EKSPORT` operation against the `klienci` table.

 The export involved **4812 records**.

---

 # 4\. Database Scope

 The total number of records in the customer table was checked with:

```
SELECT COUNT(*) FROM klienci;
```

 The result was:

```
4812
```

 This means that the number of records recorded as exported corresponds to the total number of records present in the `klienci` table.

---

 # 5\. MFA Analysis

 The database also contained a `uzytkownicy` table.

 Its structure was examined with:

```
.schema uzytkownicy
```

 The MFA field was:

```
mfa_wlaczone
```

 Instead of assuming the exact values, the distinct values were checked directly:

```
SELECT mfa_wlaczone, COUNT(*)
FROM uzytkownicy
GROUP BY mfa_wlaczone;
```

 The database contained:

```
nie | 15
tak | 2
```

 Therefore:

 - **15 users** did not have MFA enabled.
- **2 users** had MFA enabled.

---

 # 6\. Personal Data Exposure

 The structure of the customer table was:

```
.schema klienci
```

 Columns:

```
id
nazwa_firmy
osoba_kontaktowa
pesel
email
telefon
miasto
data_dodania
opiekun
```

 The table contains personal data, including information that can identify or relate to natural persons.

 Examples include:

 - `osoba_kontaktowa`
- `pesel`
- `email`
- `telefon`
- potentially `miasto` when associated with an identifiable person

 The presence of `pesel`, in particular, indicates highly sensitive personal information requiring appropriate protection.

---

 # 7\. Data Decoding

 The final investigation stage involved a sample recovered from the attacker's server.

 The provided data used two encoding layers.

 The decoding process was:

```
From Base64
        ↓
From Hex
        ↓
Readable data
```

 The data was therefore **encoded rather than encrypted**.

 No password or cryptographic key was required to perform the decoding.

 This is an important distinction: encoding changes the representation of data, while encryption is designed to protect confidentiality and normally requires a key for decryption.

---

 # 8\. Evidence

 The investigation was based on three main evidence sources:

 ### PCAP

 Used to investigate:

 - HTTP communication,
- FTP authentication,
- file transfer,
- external destination IP,
- transmitted payloads.

 ### SQLite database

 Used to investigate:

 - source IP activity,
- user account activity,
- database operations,
- exported record count,
- MFA status,
- customer data structure.

 ### Recovered encoded sample

 Used to investigate:

 - the type of encoding,
- the information contained in the recovered data,
- the presence of personal information.

---

 # 9\. Investigation Workflow

 The investigation followed a simple incident-response workflow:

```
PCAP
  │
  ├── HTTP analysis
  │
  ├── FTP analysis
  │
  └── File transfer identification
          │
          ▼
      External IP
          │
          ▼
     SQLite database
          │
          ├── Access logs
          ├── Export operation
          ├── User account
          └── MFA status
                  │
                  ▼
          Recovered data
                  │
                  ▼
       Base64 → Hex decoding
                  │
                  ▼
          Data exposure
```

---

 # 10\. Key Findings

 The investigation established the following:

 - Network traffic contained suspicious communication with an external IP address.
- HTTP `POST` traffic contained data in the request body.
- FTP authentication information was observable in the captured traffic.
- An FTP `STOR` operation transferred a file to the external host.
- Database logs associated activity with the same external IP.
- The database recorded an export of **4812 customer records**.
- The `klienci` table contained personal data.
- **15 users** had MFA disabled, while **2 users** had MFA enabled.
- Recovered data was encoded using multiple encoding layers rather than protected through encryption.

---

 # 11\. Lessons Learned

 The investigation demonstrates several important defensive security principles:

 - Sensitive information should not be transmitted using unencrypted protocols such as standard FTP.
- Network monitoring can reveal credentials and data transfers when insecure protocols are used.
- Database audit logs are valuable for reconstructing suspicious activity.
- MFA reduces the risk associated with compromised credentials.
- Encoding should not be treated as a security mechanism.
- Personal data requires appropriate technical and organizational protection.
- Correlating network evidence with application and database logs provides a more complete picture of an incident.

---

 ## 📁 Project Structure

```
NordVita-security-analysis/
│
├── README.md
│
├── raport/
│   └── raport.pdf
│
├── analiza/
│   ├── Z5_ruch_sieciowy.md
│   ├── Z6_baza_danych.md
│   └── Z7_dekodowanie.md
│
└── screenshots/
    ├── Z5_pcap.png
    ├── Z6_sql.png
    └── Z7_cyberchef.png
```

 > **Note:** Original PCAP files, databases, credentials, personal data and other sensitive training materials should not be published in a public repository. Screenshots and examples should be sanitized before publication.

---

 ## 🎯 Skills Demonstrated

 This project demonstrates practical experience with:

 `Network Traffic Analysis` · `PCAP Analysis` · `TShark` · `FTP/HTTP Investigation` · `SQLite` · `Log Analysis` · `Data Exposure Assessment` · `CyberChef` · `Incident Investigation` · `Blue Team Fundamentals`
