<?php
/**
 * Validador de Email con verificación de registros MX
 */
header('Content-Type: text/html; charset=utf-8');

$email = '';
$resultado = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');

    if ($email !== '') {
        $resultado = [
            'email' => $email,
            'checks' => [],
            'score' => 0,
            'maxScore' => 5,
        ];

        // 1) Formato válido
        $formatoOk = filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
        $resultado['checks'][] = [
            'nombre' => 'Formato de email válido',
            'ok' => $formatoOk,
            'detalle' => $formatoOk ? 'El formato del email es correcto (RFC 5322)' : 'El formato no cumple con el estándar RFC 5322',
        ];
        if ($formatoOk) $resultado['score']++;

        // Extraer dominio
        $partes = explode('@', $email);
        $dominio = $partes[1] ?? '';

        // 2) Dominio tiene formato válido
        $dominioOk = !empty($dominio) && preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $dominio);
        $resultado['checks'][] = [
            'nombre' => 'Dominio con formato válido',
            'ok' => $dominioOk,
            'detalle' => $dominioOk ? "El dominio '{$dominio}' tiene un formato correcto" : 'El dominio no tiene un formato válido',
        ];
        if ($dominioOk) $resultado['score']++;

        // 3) Registros MX
        $mxOk = false;
        $mxRecords = [];
        if ($dominioOk) {
            $mxOk = getmxrr($dominio, $mxHosts, $mxWeights);
            if ($mxOk && !empty($mxHosts)) {
                for ($i = 0; $i < count($mxHosts); $i++) {
                    $mxRecords[] = [
                        'host' => $mxHosts[$i],
                        'priority' => $mxWeights[$i] ?? 0,
                    ];
                }
                // Ordenar por prioridad
                usort($mxRecords, fn($a, $b) => $a['priority'] - $b['priority']);
            }
        }
        $resultado['checks'][] = [
            'nombre' => 'Registros MX del dominio',
            'ok' => $mxOk && !empty($mxRecords),
            'detalle' => ($mxOk && !empty($mxRecords))
                ? 'Se encontraron ' . count($mxRecords) . ' registro(s) MX'
                : 'No se encontraron registros MX — el dominio no puede recibir correos',
        ];
        if ($mxOk && !empty($mxRecords)) $resultado['score']++;
        $resultado['mx'] = $mxRecords;

        // 4) No es email desechable (lista básica)
        $desechables = ['mailinator.com','guerrillamail.com','tempmail.com','throwaway.email','yopmail.com','10minutemail.com','trashmail.com','fakeinbox.com','sharklasers.com','guerrillamailblock.com','grr.la','dispostable.com','maildrop.cc'];
        $esDesechable = in_array(strtolower($dominio), $desechables);
        $resultado['checks'][] = [
            'nombre' => 'No es email desechable/temporal',
            'ok' => !$esDesechable,
            'detalle' => $esDesechable
                ? "⚠️ '{$dominio}' es un servicio de email temporal/desechable"
                : 'El dominio no está en la lista de proveedores temporales conocidos',
        ];
        if (!$esDesechable) $resultado['score']++;

        // 5) Registro DNS A/AAAA del dominio
        $dnsOk = false;
        if ($dominioOk) {
            $dnsA = @dns_get_record($dominio, DNS_A);
            $dnsAAAA = @dns_get_record($dominio, DNS_AAAA);
            $dnsOk = (!empty($dnsA) || !empty($dnsAAAA));
        }
        $resultado['checks'][] = [
            'nombre' => 'DNS del dominio resuelve (A/AAAA)',
            'ok' => $dnsOk,
            'detalle' => $dnsOk
                ? "El dominio '{$dominio}' resuelve correctamente en DNS"
                : "El dominio '{$dominio}' no tiene registros DNS A/AAAA",
        ];
        if ($dnsOk) $resultado['score']++;
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Validador de Email con registros MX Online | ConfiguroWeb</title>
<meta name="description" content="Valida direcciones de email verificando formato, registros MX del dominio y DNS. Detecta emails desechables. Gratis.">
<meta name="keywords" content="validador email, verificar email, registros mx, dns email, email desechable, email válido">
<meta property="og:type" content="website">
<meta property="og:title" content="Validador de Email con registros MX Online">
<meta property="og:description" content="Valida direcciones de email verificando formato, registros MX y DNS online gratis.">
<link rel="canonical" href="https://demoscweb.com/github/php-validador-email-mx/">
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"WebApplication","name":"Validador Email MX","applicationCategory":"UtilitiesApplication","operatingSystem":"Any","offers":{"@type":"Offer","price":"0","priceCurrency":"USD"},"author":{"@type":"Person","name":"ConfiguroWeb","url":"https://configuroweb.com"}}
</script>
<link rel="stylesheet" href="assets/style.css">
</head>
<body>
<header>
  <h1>✉️ Validador de Email y Registros MX</h1>
  <p class="subtitle">Verifica formato, DNS y registros MX de cualquier email</p>
</header>
<main>
  <form method="POST">
    <label for="email">Dirección de email a validar</label>
    <input type="text" name="email" id="email" value="<?php echo htmlspecialchars($email); ?>" placeholder="usuario@ejemplo.com" required>
    <button type="submit" class="btn-primary">✉️ Validar Email</button>
  </form>

  <?php if ($resultado): ?>
  <!-- Score -->
  <div class="resultado" style="margin-top:1.5rem;background:linear-gradient(135deg,<?php echo $resultado['score'] >= 4 ? '#052e1a,#10b981' : ($resultado['score'] >= 2 ? '#422006,#f59e0b' : '#450a0a,#ef4444'); ?>)">
    <span class="etiqueta">Puntuación de validez</span>
    <div class="valor"><?php echo $resultado['score']; ?>/<?php echo $resultado['maxScore']; ?></div>
    <p style="margin-top:.3rem;opacity:.8">
      <?php
      if ($resultado['score'] >= 4) echo '✅ Email probablemente válido';
      elseif ($resultado['score'] >= 2) echo '⚠️ Email con problemas';
      else echo '❌ Email probablemente inválido';
      ?>
    </p>
  </div>

  <!-- Checks detallados -->
  <div style="margin-top:1rem">
    <?php foreach ($resultado['checks'] as $check): ?>
    <div style="background:var(--surface);padding:.8rem 1rem;border-radius:var(--radius);margin-bottom:.5rem;border-left:3px solid <?php echo $check['ok'] ? 'var(--success)' : '#ef4444'; ?>">
      <div style="display:flex;align-items:center;gap:.5rem">
        <span><?php echo $check['ok'] ? '✅' : '❌'; ?></span>
        <strong style="font-size:.9rem"><?php echo htmlspecialchars($check['nombre']); ?></strong>
      </div>
      <p style="color:var(--muted);font-size:.8rem;margin-top:.2rem;margin-left:1.5rem"><?php echo htmlspecialchars($check['detalle']); ?></p>
    </div>
    <?php endforeach; ?>
  </div>

  <!-- Registros MX -->
  <?php if (!empty($resultado['mx'])): ?>
  <div style="background:var(--surface);padding:1rem;border-radius:var(--radius);margin-top:1rem">
    <h3 style="font-size:.95rem;margin-bottom:.5rem">📧 Registros MX encontrados</h3>
    <?php foreach ($resultado['mx'] as $mx): ?>
    <div style="display:flex;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid var(--border);font-size:.85rem">
      <code style="color:#93c5fd;font-family:'Cascadia Code',Consolas,monospace"><?php echo htmlspecialchars($mx['host']); ?></code>
      <span style="color:var(--muted)">Prioridad: <?php echo $mx['priority']; ?></span>
    </div>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>
  <?php endif; ?>

  <section class="info">
    <h2>¿Qué se verifica?</h2>
    <p><strong>Formato RFC 5322:</strong> Verifica que la estructura del email sea correcta (usuario@dominio.ext).</p>
    <p><strong>Registros MX:</strong> Confirma que el dominio tiene servidores de correo configurados para recibir emails.</p>
    <p><strong>DNS A/AAAA:</strong> Verifica que el dominio existe y resuelve en Internet.</p>
    <p><strong>Email desechable:</strong> Detecta dominios de email temporal como Mailinator, Guerrilla Mail, etc.</p>
    <p style="color:var(--muted);font-size:.85rem;margin-top:.5rem">⚠️ Esta herramienta NO envía un email de prueba. Verifica la infraestructura del dominio, pero no garantiza que el buzón específico exista.</p>
  </section>
</main>
<footer>
  <p>Desarrollado por <a href="https://configuroweb.com" target="_blank">ConfiguroWeb</a> ·
     <a href="https://appscweb.com/citas/" target="_blank">Sistema de Citas</a> ·
     <a href="https://appscweb.com/negocios/" target="_blank">Gestión de Negocios</a></p>
  <p>&copy; <?php echo date('Y'); ?> ConfiguroWeb</p>
</footer>
<script src="assets/script.js"></script>
</body>
</html>
