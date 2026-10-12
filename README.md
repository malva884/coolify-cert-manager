# Coolify Cert Manager

Webapp PHP minimale per caricare certificati SSL custom su Coolify/Traefik **senza SSH, FileZilla o PuTTY**.

## Come funziona

Coolify monta `/data/coolify/proxy` dell'host dentro il container `coolify-proxy` (Traefik) al path `/traefik`.
Questa app scrive i certificati in `/data/coolify/proxy/certs` tramite bind mount e rigenera il file di
dynamic configuration `/data/coolify/proxy/dynamic/custom-certificates.yaml`, che Traefik ricarica
automaticamente (file provider con watch attivo).

## Funzionalità

- Upload certificato `.crt/.pem` + chiave `.key` (file o PEM incollato)
- Validazione: parsing X.509 e verifica corrispondenza cert/chiave prima di scrivere
- Nome file derivato dal Common Name (`*.example.com` → `wildcard.example.com`)
- Tabella certificati installati con SAN, emittente, scadenza e badge stato (>30gg / ≤30gg / scaduto)
- Eliminazione certificati con rigenerazione automatica dello YAML
- Login con password singola (`ADMIN_PASSWORD`), sessione + CSRF

## Deploy su Coolify

1. **Pusha questo progetto** su un repo Git (o usa "Deploy from Dockerfile/compose").
2. Su Coolify: **New Resource** → il progetto. Coolify rileva il `Dockerfile` automaticamente.
   - In alternativa usa "Docker Compose" con il `docker-compose.yml` incluso.
3. **Environment Variables**: aggiungi `ADMIN_PASSWORD` con una password robusta.
4. **Storages / Persistent Storage** — crea due bind mount (fondamentale):

   | Source (host) | Destination (container) |
   |---|---|
   | `/data/coolify/proxy/certs` | `/proxy/certs` |
   | `/data/coolify/proxy/dynamic` | `/proxy/dynamic` |

   > Se usi `docker-compose.yml` i volumi sono già dichiarati: salta questo passo.

5. Assegna un dominio alla risorsa (es. `certs.tuodominio.it`) con HTTPS.
6. Deploy, apri il dominio, accedi con `ADMIN_PASSWORD`, carica certificato e chiave.

## Requisiti sui file

- Certificato in formato **PEM fullchain** (cert + intermedi concatenati)
- Chiave privata **PEM non cifrata**
- Se converti da PFX: `openssl pkcs12 -in cert.pfx -out cert.pem -clcerts` (cert) e `-nocerts -nodes` (key)

## Note

- L'entrypoint fa `chown www-data` sulle due directory montate: Traefik gira come root e continua a leggerle.
- Dopo l'upload Traefik applica il certificato entro pochi secondi; se non lo vedi, riavvia il proxy
  da Coolify: **Servers → [server] → Proxy → Restart**.
- Per difesa in più puoi aggiungere una IP allowlist sulla route di Traefik da Coolify.

## Struttura

```
├── Dockerfile
├── docker-entrypoint.sh   # chown delle dir montate + exec apache
├── docker-compose.yml     # alternativa al Dockerfile puro
├── public/index.php       # UI: login, upload, lista, delete
└── src/CertStore.php      # logica certificati + YAML Traefik
```
