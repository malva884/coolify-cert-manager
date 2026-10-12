<?php

declare(strict_types=1);

/**
 * Gestisce i certificati SSL custom per Traefik/Coolify.
 *
 * Scrive le coppie <base>.cert / <base>.key nella directory certs
 * e rigenera il file YAML di dynamic configuration che Traefik osserva.
 */
final class CertStore
{
    public function __construct(
        private readonly string $certsDir,
        private readonly string $dynamicDir,
        private readonly string $dynamicFile = 'custom-certificates.yaml',
    ) {
    }

    /**
     * Elenca le coppie cert/key presenti con metadati del certificato.
     *
     * @return array<int, array<string, mixed>>
     */
    public function list(): array
    {
        $out = [];
        foreach (glob($this->certsDir . '/*.cert') ?: [] as $certFile) {
            $base = basename($certFile, '.cert');
            $keyFile = $this->certsDir . '/' . $base . '.key';

            $pem = @file_get_contents($certFile);
            $info = $pem !== false ? @openssl_x509_parse($pem) : false;

            $sans = [];
            if (is_array($info) && isset($info['extensions']['subjectAltName'])) {
                $sans = array_map(
                    static fn(string $s) => trim(substr($s, 4)),
                    explode(',', (string) $info['extensions']['subjectAltName'])
                );
            }

            $out[] = [
                'base'        => $base,
                'cn'          => $info['subject']['CN'] ?? $base,
                'sans'        => $sans,
                'issuer'      => $info['issuer']['O'] ?? ($info['issuer']['CN'] ?? '?'),
                'valid_from'  => $info['validFrom_time_t'] ?? null,
                'valid_to'    => $info['validTo_time_t'] ?? null,
                'has_key'     => is_file($keyFile),
                'parse_error' => $info === false,
            ];
        }

        usort($out, static fn(array $a, array $b) => ($a['valid_to'] ?? PHP_INT_MAX) <=> ($b['valid_to'] ?? PHP_INT_MAX));

        return $out;
    }

    /**
     * Valida e installa una coppia certificato/chiave PEM.
     *
     * @return array{base: string, cn: string, sans: string[], valid_to: int|null}
     * @throws RuntimeException
     */
    public function install(string $certPem, string $keyPem): array
    {
        $certPem = $this->normalizePem($certPem);
        $keyPem  = $this->normalizePem($keyPem);

        $info = @openssl_x509_parse($certPem);
        if ($info === false) {
            throw new RuntimeException('Certificato non valido: impossibile fare il parsing del PEM.');
        }
        if (!@openssl_x509_check_private_key($certPem, $keyPem)) {
            throw new RuntimeException('La chiave privata non corrisponde al certificato.');
        }

        $base = $this->sanitize((string) ($info['subject']['CN'] ?? 'certificate'));
        if ($base === '') {
            $base = 'certificate-' . date('Ymd-His');
        }

        $this->ensureDirs();
        $this->atomicWrite($this->certsDir . '/' . $base . '.cert', $certPem, 0644);
        $this->atomicWrite($this->certsDir . '/' . $base . '.key', $keyPem, 0600);
        $this->regenerateDynamicConfig();

        return [
            'base'     => $base,
            'cn'       => (string) ($info['subject']['CN'] ?? $base),
            'sans'     => isset($info['extensions']['subjectAltName'])
                ? array_map(static fn(string $s) => trim(substr($s, 4)), explode(',', (string) $info['extensions']['subjectAltName']))
                : [],
            'valid_to' => $info['validTo_time_t'] ?? null,
        ];
    }

    /**
     * Elimina una coppia cert/key e aggiorna il YAML dinamico.
     */
    public function delete(string $base): void
    {
        $base = basename($base); // anti path traversal
        @unlink($this->certsDir . '/' . $base . '.cert');
        @unlink($this->certsDir . '/' . $base . '.key');
        $this->regenerateDynamicConfig();
    }

    /**
     * Rigenera il file YAML di dynamic configuration per Traefik.
     * I path dentro il container Traefik sono /traefik/certs.
     */
    private function regenerateDynamicConfig(): void
    {
        $pairs = [];
        foreach (glob($this->certsDir . '/*.cert') ?: [] as $certFile) {
            $base = basename($certFile, '.cert');
            if (is_file($this->certsDir . '/' . $base . '.key')) {
                $pairs[] = $base;
            }
        }
        sort($pairs);

        $yaml = "# Generato da coolify-cert-manager - non modificare a mano\ntls:\n  certificates:\n";
        foreach ($pairs as $base) {
            $yaml .= "    - certFile: /traefik/certs/{$base}.cert\n"
                   . "      keyFile: /traefik/certs/{$base}.key\n";
        }

        $this->ensureDirs();
        $this->atomicWrite($this->dynamicDir . '/' . $this->dynamicFile, $yaml, 0644);
    }

    private function normalizePem(string $pem): string
    {
        return rtrim(str_replace(["\r\n", "\r"], "\n", $pem)) . "\n";
    }

    private function sanitize(string $name): string
    {
        $name = strtolower(trim($name));
        $name = str_starts_with($name, '*.') ? 'wildcard.' . substr($name, 2) : $name;

        return (string) preg_replace('/[^a-z0-9.\-_]/', '-', $name);
    }

    private function ensureDirs(): void
    {
        foreach ([$this->certsDir, $this->dynamicDir] as $dir) {
            if (!is_dir($dir) && !@mkdir($dir, 0775, true)) {
                throw new RuntimeException("Impossibile creare la directory: {$dir}");
            }
        }
    }

    private function atomicWrite(string $path, string $contents, int $mode): void
    {
        $tmp = $path . '.tmp';
        if (@file_put_contents($tmp, $contents) === false) {
            throw new RuntimeException("Scrittura fallita: {$path} (permessi?)");
        }
        @chmod($tmp, $mode);
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw new RuntimeException("Impossibile spostare il file in: {$path}");
        }
    }
}
