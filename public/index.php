<?php

declare(strict_types=1);

session_start();
require __DIR__ . '/../src/CertStore.php';

$adminPassword = (string) (getenv('ADMIN_PASSWORD') ?: '');
$store = new CertStore(
    (string) (getenv('CERTS_DIR') ?: '/proxy/certs'),
    (string) (getenv('DYNAMIC_DIR') ?: '/proxy/dynamic'),
    (string) (getenv('DYNAMIC_FILE') ?: 'custom-certificates.yaml'),
);

function e(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

function flash(string $type, string $msg): void
{
    $_SESSION['flash'] = ['type' => $type, 'msg' => $msg];
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function checkCsrf(): void
{
    if (!hash_equals((string) ($_SESSION['csrf'] ?? ''), (string) ($_POST['csrf'] ?? ''))) {
        http_response_code(403);
        exit('CSRF token non valido.');
    }
}

// ---------- POST ----------

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $adminPassword !== '') {
    $action = (string) ($_POST['action'] ?? '');

    if ($action === 'login') {
        if (hash_equals($adminPassword, (string) ($_POST['password'] ?? ''))) {
            session_regenerate_id(true);
            $_SESSION['auth'] = true;
        } else {
            flash('error', 'Password errata.');
        }
        header('Location: ' . $_SERVER['REQUEST_URI']);
        exit;
    }

    if ($action === 'logout') {
        $_SESSION = [];
        session_destroy();
        session_start();
        header('Location: ' . $_SERVER['REQUEST_URI']);
        exit;
    }

    if (empty($_SESSION['auth'])) {
        http_response_code(403);
        exit('Non autenticato.');
    }
    checkCsrf();

    try {
        if ($action === 'upload') {
            $certPem = trim((string) ($_POST['cert_pem'] ?? ''));
            $keyPem  = trim((string) ($_POST['key_pem'] ?? ''));

            if ($certPem === '' && is_uploaded_file($_FILES['cert_file']['tmp_name'] ?? '')) {
                $certPem = (string) file_get_contents($_FILES['cert_file']['tmp_name']);
            }
            if ($keyPem === '' && is_uploaded_file($_FILES['key_file']['tmp_name'] ?? '')) {
                $keyPem = (string) file_get_contents($_FILES['key_file']['tmp_name']);
            }

            if ($certPem === '' || $keyPem === '') {
                throw new RuntimeException('Servono sia il certificato sia la chiave privata (file o testo PEM).');
            }

            $res = $store->install($certPem, $keyPem);
            flash('ok', "Certificato installato: {$res['base']} (scadenza: " . date('d/m/Y', $res['valid_to'] ?? time()) . '). Traefik lo carica automaticamente.');
        } elseif ($action === 'delete') {
            $store->delete((string) ($_POST['base'] ?? ''));
            flash('ok', 'Certificato eliminato.');
        }
    } catch (Throwable $ex) {
        flash('error', $ex->getMessage());
    }

    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
}

$authed = !empty($_SESSION['auth']);
$certs = $authed ? $store->list() : [];
$flashMsg = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
$csrf = csrfToken();
$now = time();
?>
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Coolify Cert Manager</title>
<style>
:root{--bg:#0f1220;--card:#1a1e33;--border:#2a2f4a;--txt:#e6e9f5;--mut:#8a90b3;--ok:#3ecf8e;--warn:#f5a623;--err:#ef5350;--acc:#5b8cff}
*{box-sizing:border-box;margin:0}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--txt);min-height:100vh;padding:2rem 1rem}
.wrap{max-width:960px;margin:0 auto}
h1{font-size:1.4rem;margin-bottom:.25rem}
.sub{color:var(--mut);font-size:.85rem;margin-bottom:1.5rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.25rem;margin-bottom:1.5rem}
.card h2{font-size:1rem;margin-bottom:1rem;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}
label{display:block;font-size:.8rem;color:var(--mut);margin:.75rem 0 .3rem}
input[type=file],input[type=password]{width:100%;padding:.5rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--txt);font-size:.85rem}
textarea{width:100%;min-height:110px;padding:.5rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--txt);font-family:ui-monospace,Consolas,monospace;font-size:.75rem;resize:vertical}
button,.btn{padding:.55rem 1.1rem;border:0;border-radius:8px;background:var(--acc);color:#fff;font-size:.85rem;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.1)}
.btn-del{background:transparent;border:1px solid var(--err);color:var(--err);padding:.3rem .7rem;font-size:.75rem}
.btn-del:hover{background:var(--err);color:#fff}
.btn-out{background:transparent;border:1px solid var(--border);color:var(--mut);font-size:.75rem;padding:.3rem .7rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;color:var(--mut);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;padding:.5rem .4rem;border-bottom:1px solid var(--border)}
td{padding:.6rem .4rem;border-bottom:1px solid var(--border);vertical-align:top}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:.78rem}
.sans{color:var(--mut);font-size:.75rem}
.badge{display:inline-block;padding:.15rem .55rem;border-radius:99px;font-size:.72rem;font-weight:700}
.b-ok{background:rgba(62,207,142,.15);color:var(--ok)}
.b-warn{background:rgba(245,166,35,.15);color:var(--warn)}
.b-err{background:rgba(239,83,80,.15);color:var(--err)}
.flash{padding:.7rem 1rem;border-radius:8px;margin-bottom:1.25rem;font-size:.85rem}
.flash.ok{background:rgba(62,207,142,.12);border:1px solid var(--ok);color:var(--ok)}
.flash.error{background:rgba(239,83,80,.12);border:1px solid var(--err);color:var(--err)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:720px){.grid2{grid-template-columns:1fr}}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem}
.login{max-width:380px;margin:12vh auto 0}
.hint{font-size:.75rem;color:var(--mut);margin-top:.4rem}
.empty{color:var(--mut);text-align:center;padding:1.5rem 0;font-size:.85rem}
</style>
</head>
<body>
<?php if ($adminPassword === ''): ?>
<div class="wrap"><div class="card">
<h1>Configurazione mancante</h1>
<p class="hint">Imposta la variabile d'ambiente <span class="mono">ADMIN_PASSWORD</span> su Coolify e ridistribuisci l'app.</p>
</div></div>
<?php elseif (!$authed): ?>
<div class="login"><div class="card">
<h1>Coolify Cert Manager</h1>
<p class="sub">Accesso riservato</p>
<?php if ($flashMsg): ?><div class="flash <?= e($flashMsg['type']) ?>"><?= e($flashMsg['msg']) ?></div><?php endif; ?>
<form method="post">
<input type="hidden" name="action" value="login">
<label>Password</label>
<input type="password" name="password" autofocus required>
<div style="margin-top:1rem"><button type="submit">Accedi</button></div>
</form>
</div></div>
<?php else: ?>
<div class="wrap">
<div class="top">
<div>
<h1>Coolify Cert Manager</h1>
<p class="sub mono"><?= e(getenv('CERTS_DIR') ?: '/proxy/certs') ?> &rarr; /traefik/certs</p>
</div>
<form method="post"><input type="hidden" name="action" value="logout"><button class="btn-out" type="submit">Esci</button></form>
</div>

<?php if ($flashMsg): ?><div class="flash <?= e($flashMsg['type']) ?>"><?= e($flashMsg['msg']) ?></div><?php endif; ?>

<div class="card">
<h2>Carica certificato</h2>
<form method="post" enctype="multipart/form-data">
<input type="hidden" name="action" value="upload">
<input type="hidden" name="csrf" value="<?= e($csrf) ?>">
<div class="grid2">
<div>
<label>File certificato (.crt/.pem, fullchain)</label>
<input type="file" name="cert_file" accept=".crt,.cert,.pem,.cer">
<label>oppure incolla il PEM</label>
<textarea name="cert_pem" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
</div>
<div>
<label>File chiave privata (.key)</label>
<input type="file" name="key_file" accept=".key,.pem">
<label>oppure incolla il PEM</label>
<textarea name="key_pem" placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
</div>
</div>
<p class="hint">Il nome file deriva dal Common Name del certificato. I file esistenti con lo stesso CN vengono sovrascritti.</p>
<div style="margin-top:.75rem"><button type="submit">Installa certificato</button></div>
</form>
</div>

<div class="card">
<h2>Certificati installati (<?= count($certs) ?>)</h2>
<?php if (!$certs): ?>
<p class="empty">Nessun certificato presente.</p>
<?php else: ?>
<table>
<tr><th>Dominio (CN)</th><th>SAN</th><th>Emittente</th><th>Scadenza</th><th>Stato</th><th></th></tr>
<?php foreach ($certs as $c):
    $days = $c['valid_to'] !== null ? intdiv($c['valid_to'] - $now, 86400) : null;
    $cls = $days === null ? 'b-err' : ($days < 0 ? 'b-err' : ($days <= 30 ? 'b-warn' : 'b-ok'));
    $label = $days === null ? 'errore' : ($days < 0 ? 'scaduto' : $days . ' gg');
?>
<tr>
<td class="mono"><?= e($c['cn']) ?><?php if (!$c['has_key']): ?> <span class="badge b-err">key mancante</span><?php endif; ?></td>
<td class="sans"><?= e(implode(', ', $c['sans'])) ?></td>
<td class="sans"><?= e((string) $c['issuer']) ?></td>
<td class="mono"><?= $c['valid_to'] ? e(date('d/m/Y', $c['valid_to'])) : '-' ?></td>
<td><span class="badge <?= $cls ?>"><?= e($label) ?></span></td>
<td>
<form method="post" onsubmit="return confirm('Eliminare <?= e($c['base']) ?>?')">
<input type="hidden" name="action" value="delete">
<input type="hidden" name="csrf" value="<?= e($csrf) ?>">
<input type="hidden" name="base" value="<?= e($c['base']) ?>">
<button class="btn-del" type="submit">Elimina</button>
</form>
</td>
</tr>
<?php endforeach; ?>
</table>
<p class="hint">Traefik osserva la dynamic configuration: nuovi certificati vengono applicati entro pochi secondi. In caso di problemi riavvia il proxy da Coolify (Servers &rarr; Proxy &rarr; Restart).</p>
<?php endif; ?>
</div>
</div>
<?php endif; ?>
</body>
</html>
