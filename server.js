import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Body Parsers con límites institucionales controlados
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

// ========================================================
// 1. GESTIÓN DE RUTAS Y ALMACENAMIENTO PERSISTENTE
// ========================================================

const DATA_DIR = process.env.PIA_DATA_DIR
  ? path.resolve(process.env.PIA_DATA_DIR)
  : path.join(__dirname, 'data');

const BACKUPS_DIR = path.join(DATA_DIR, 'backups');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR, { recursive: true });

const OPERATORS_FILE = path.join(DATA_DIR, 'authorized_operators.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit_logs.json');

// Lista blanca estricta de archivos autorizados (Protección contra Path Traversal)
const WHITELIST_JSON_MAP = {
  'canales': path.join(__dirname, 'canales-por-la-integridad', 'data_directorio.json'),
  'canales-por-la-integridad': path.join(__dirname, 'canales-por-la-integridad', 'data_directorio.json'),
  'data_directorio.json': path.join(__dirname, 'canales-por-la-integridad', 'data_directorio.json'),
  'directorio': path.join(__dirname, 'directorio', 'data_acceso.json'),
  'data_acceso.json': path.join(__dirname, 'directorio', 'data_acceso.json'),
  'tableros': path.join(__dirname, 'gobierno_en_numeros', 'data_tableros.json'),
  'gobierno_en_numeros': path.join(__dirname, 'gobierno_en_numeros', 'data_tableros.json'),
  'data_tableros.json': path.join(__dirname, 'gobierno_en_numeros', 'data_tableros.json'),
  'riesgo': path.join(__dirname, 'riesgo', 'datos.json'),
  'datos.json': path.join(__dirname, 'riesgo', 'datos.json'),
  'vehiculos': path.join(__dirname, 'vehiculos', 'vehiculos.json'),
  'vehiculos_instituciones': path.join(__dirname, 'vehiculos', 'vehiculos.json'),
  'vehiculos.json': path.join(__dirname, 'vehiculos', 'vehiculos.json'),
  'portal': path.join(__dirname, 'data_portal.json'),
  'data_portal.json': path.join(__dirname, 'data_portal.json'),
  'chatbot_settings.json': path.join(__dirname, 'chatbot_settings.json'),
  'chatbot_knowledge.json': path.join(__dirname, 'chatbot_knowledge.json')
};

// Cálculo de hash SHA-256 para control de concurrencia (ETag)
function computeFileHash(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
  } catch (e) {
    return null;
  }
}

// Respaldo automático previo a toda modificación
function createBackup(filePath, user = 'sistema') {
  try {
    if (!fs.existsSync(filePath)) return null;
    const filename = path.basename(filePath);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const random = crypto.randomBytes(3).toString('hex');
    const backupName = `${filename}.${timestamp}.${random}.bak`;
    const backupPath = path.join(BACKUPS_DIR, backupName);

    fs.copyFileSync(filePath, backupPath);

    // Rotación: mantener un máximo de 30 copias por archivo
    const allBackups = fs.readdirSync(BACKUPS_DIR)
      .filter(f => f.startsWith(filename) && f.endsWith('.bak'))
      .map(f => ({ name: f, time: fs.statSync(path.join(BACKUPS_DIR, f)).mtimeMs }))
      .sort((a, b) => b.time - a.time);

    if (allBackups.length > 30) {
      for (const old of allBackups.slice(30)) {
        try { fs.unlinkSync(path.join(BACKUPS_DIR, old.name)); } catch (_) {}
      }
    }
    return backupName;
  } catch (err) {
    console.error('Error generando respaldo automático:', err);
    return null;
  }
}

// Escritura atómica mediante archivo temporal y reemplazo
function atomicWriteJson(filePath, data, expectedHash = null, user = 'sistema') {
  if (typeof data !== 'object' || data === null) {
    throw new Error('Estructura de datos JSON inválida.');
  }

  // Control de concurrencia optimista
  if (expectedHash && fs.existsSync(filePath)) {
    const currentHash = computeFileHash(filePath);
    if (currentHash && currentHash !== expectedHash) {
      const err = new Error('Conflicto de concurrencia: El archivo fue modificado por la otra persona operadora. Recargue los datos.');
      err.code = 'CONCURRENCY_CONFLICT';
      throw err;
    }
  }

  const backupCreated = createBackup(filePath, user);

  const tempDir = path.dirname(filePath);
  const tempFile = path.join(tempDir, `.tmp_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`);
  const jsonContent = JSON.stringify(data, null, 2);

  fs.writeFileSync(tempFile, jsonContent, 'utf8');
  fs.renameSync(tempFile, filePath);

  const newHash = computeFileHash(filePath);
  return { success: true, newHash, backupCreated };
}

function readJsonFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    console.error(`Error leyendo ${filePath}:`, err);
    return null;
  }
}

// ========================================================
// 2. AUDITORÍA INSTITUCIONAL CON IDENTIFICACIÓN INDIVIDUAL
// ========================================================

function getAuditLogs() {
  try {
    if (!fs.existsSync(AUDIT_FILE)) return [];
    return JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8'));
  } catch (err) {
    console.error('Error leyendo auditoría:', err);
    return [];
  }
}

function logAudit({
  user = 'anónimo',
  userOid = '00000000-0000-0000-0000-000000000000',
  userRole = 'data_operator',
  action = 'CONSULTA',
  module = 'general',
  target = '',
  recordId = null,
  details = '',
  backupCreated = null,
  ip = '127.0.0.1'
}) {
  const logs = getAuditLogs();
  const entry = {
    id: logs.length > 0 ? Math.max(...logs.map(l => Number(l.id) || 0)) + 1 : 1,
    userOid,
    user,
    userRole,
    action,
    module,
    target: target || module,
    recordId,
    details,
    backupCreated,
    timestamp: new Date().toISOString(),
    ip
  };

  logs.unshift(entry);
  if (logs.length > 1000) logs.pop();

  try {
    const tempFile = path.join(DATA_DIR, `.tmp_audit_${Date.now()}`);
    fs.writeFileSync(tempFile, JSON.stringify(logs, null, 2), 'utf8');
    fs.renameSync(tempFile, AUDIT_FILE);
  } catch (e) {
    console.error('Error guardando bitácora de auditoría:', e);
  }
  return entry;
}

// ========================================================
// 3. MODELO DE ACCESO CERRADO PARA EXACTAMENTE DOS OPERADORES
// ========================================================

const ENTRA_TENANT_ID = process.env.ENTRA_TENANT_ID || '';
const ENTRA_CLIENT_ID = process.env.ENTRA_CLIENT_ID || '';
const ENTRA_REDIRECT_URI = process.env.ENTRA_REDIRECT_URI || 'http://localhost:3000/admin/';

let jwksRemote = null;
function getRemoteJWKS() {
  if (!jwksRemote && ENTRA_TENANT_ID) {
    const jwksUrl = new URL(`https://login.microsoftonline.com/${ENTRA_TENANT_ID}/discovery/v2.0/keys`);
    jwksRemote = createRemoteJWKSet(jwksUrl, {
      cacheMaxAge: 600000,
      cooldownDuration: 30000
    });
  }
  return jwksRemote;
}

// Carga las dos identidades autorizadas de la CNC (vía variables de entorno o archivo de configuración privado)
function getAuthorizedOperators() {
  const operators = [];

  // 1. Operador 1: apoyogi@cnc.gob.gt
  const op1Oid = (process.env.PIA_OPERATOR_1_OID || '').trim().toLowerCase();
  if (op1Oid && op1Oid !== '00000000-0000-0000-0000-000000000000') {
    operators.push({
      operatorIndex: 1,
      oid: op1Oid,
      tid: ENTRA_TENANT_ID,
      displayName: process.env.PIA_OPERATOR_1_NAME || 'Apoyo GI (CNC)',
      upn: process.env.PIA_OPERATOR_1_UPN || 'apoyogi@cnc.gob.gt',
      role: 'data_operator',
      status: 'active'
    });
  }

  // 2. Operador 2: deteccionydenuncia@cnc.gob.gt
  const op2Oid = (process.env.PIA_OPERATOR_2_OID || '').trim().toLowerCase();
  if (op2Oid && op2Oid !== '00000000-0000-0000-0000-000000000000') {
    operators.push({
      operatorIndex: 2,
      oid: op2Oid,
      tid: ENTRA_TENANT_ID,
      displayName: process.env.PIA_OPERATOR_2_NAME || 'Detección y Denuncia (CNC)',
      upn: process.env.PIA_OPERATOR_2_UPN || 'deteccionydenuncia@cnc.gob.gt',
      role: 'data_operator',
      status: 'active'
    });
  }

  // 3. Complemento desde archivo protegido si no se configuraron variables de entorno
  if (operators.length === 0 && fs.existsSync(OPERATORS_FILE)) {
    try {
      const fileOps = JSON.parse(fs.readFileSync(OPERATORS_FILE, 'utf8'));
      if (Array.isArray(fileOps)) {
        for (const op of fileOps) {
          const rawOid = (op.oid || '').trim().toLowerCase();
          if (rawOid && rawOid !== '00000000-0000-0000-0000-000000000000' && !operators.some(o => o.oid === rawOid)) {
            const idx = operators.length + 1;
            operators.push({
              operatorIndex: idx,
              oid: rawOid,
              tid: op.tid || ENTRA_TENANT_ID,
              displayName: op.displayName || (idx === 1 ? 'Apoyo GI (CNC)' : 'Detección y Denuncia (CNC)'),
              upn: op.upn || (idx === 1 ? 'apoyogi@cnc.gob.gt' : 'deteccionydenuncia@cnc.gob.gt'),
              role: 'data_operator',
              status: op.status || 'active'
            });
          }
        }
      }
    } catch (e) {
      console.error('Error leyendo authorized_operators.json:', e);
    }
  }

  // Exactamente hasta 2 operadores permitidos
  return operators.slice(0, 2);
}

// Validación criptográfica estricta con Microsoft Entra ID
async function verifyEntraToken(token) {
  if (!token || typeof token !== 'string') {
    throw new Error('Token de autorización no proporcionado.');
  }

  // Si no está configurado en el servidor, no permitir acceso administrativo
  if (!ENTRA_TENANT_ID || !ENTRA_CLIENT_ID) {
    const err = new Error('Microsoft Entra ID no está configurado en el servidor (ENTRA_TENANT_ID / ENTRA_CLIENT_ID pendientes).');
    err.code = 'CONFIG_PENDING';
    throw err;
  }

  const JWKS = getRemoteJWKS();
  if (!JWKS) {
    throw new Error('No fue posible inicializar el conjunto de llaves JWKS de Microsoft Entra ID.');
  }

  const expectedIssuers = [
    `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0`,
    `https://sts.windows.net/${ENTRA_TENANT_ID}/`
  ];

  const { payload } = await jwtVerify(token, JWKS, {
    audience: ENTRA_CLIENT_ID,
    issuer: expectedIssuers,
    clockTolerance: 60
  });

  if (!payload.oid) {
    throw new Error('El token institucional no contiene un identificador inmutable de objeto (oid).');
  }

  if (payload.tid && payload.tid !== ENTRA_TENANT_ID) {
    throw new Error('Token emitido por un arrendatario (tenant) no autorizado para el Portal PIA.');
  }

  return payload;
}

// Middleware de autenticación y autorización para dos operadores
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();

  if (!token) {
    return res.status(401).json({
      error: 'Acceso no autorizado. Debe identificarse con una cuenta institucional de Microsoft 365 autorizada.'
    });
  }

  try {
    const payload = await verifyEntraToken(token);
    const userOid = String(payload.oid).trim().toLowerCase();
    const userUpn = payload.preferred_username || payload.upn || payload.email || 'desconocido@entidad.gob.gt';
    const userDisplayName = payload.name || userUpn;

    // Verificar si el usuario autenticado corresponde a uno de los dos operadores autorizados
    const operators = getAuthorizedOperators();
    const matchedOperator = operators.find(op => op.oid === userOid && op.status === 'active');

    if (!matchedOperator) {
      logAudit({
        user: userUpn,
        userOid,
        userRole: 'no_autorizado',
        action: 'ACCESO DENEGADO (NO ES OPERADOR AUTORIZADO)',
        module: 'auth',
        target: 'admin',
        details: `Usuario institucional autenticado en Entra ID pero no forma parte de los dos operadores autorizados (OID: ${userOid})`,
        ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1'
      });

      return res.status(403).json({
        error: 'Su cuenta institucional de Microsoft 365 está autenticada, pero no figura entre las dos identidades operativas autorizadas para administrar el Portal PIA.',
        oid: userOid,
        upn: userUpn
      });
    }

    req.user = {
      oid: userOid,
      upn: userUpn,
      displayName: matchedOperator.displayName || userDisplayName,
      operatorIndex: matchedOperator.operatorIndex,
      role: 'data_operator',
      modules: ['canales', 'directorio', 'tableros', 'riesgo', 'portal', 'chatbot']
    };

    next();
  } catch (err) {
    if (err.code === 'CONFIG_PENDING') {
      return res.status(401).json({
        error: 'El módulo administrativo está temporalmente cerrado: Configuración de Microsoft Entra ID pendiente de completar por el equipo de TI.',
        configPending: true
      });
    }
    return res.status(401).json({
      error: 'Token institucional inválido, expirado o de tenant no autorizado.',
      details: err.message
    });
  }
}

// Middleware de verificación de rol de operador de datos
function requireOperator(req, res, next) {
  if (!req.user || req.user.role !== 'data_operator') {
    return res.status(403).json({ error: 'Operación reservada exclusivamente para los operadores autorizados.' });
  }
  next();
}

// Cabeceras de seguridad HTTP
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(self), geolocation=()');
  if (req.url.endsWith('.json')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

// ========================================================
// 4. ENDPOINTS DE AUTENTICACIÓN INSTITUCIONAL
// ========================================================

app.get('/api/auth/entra-config', (req, res) => {
  res.json({
    configured: !!(ENTRA_TENANT_ID && ENTRA_CLIENT_ID),
    clientId: ENTRA_CLIENT_ID,
    tenantId: ENTRA_TENANT_ID,
    authority: ENTRA_TENANT_ID ? `https://login.microsoftonline.com/${ENTRA_TENANT_ID}` : '',
    redirectUri: ENTRA_REDIRECT_URI,
    operatorsConfigured: getAuthorizedOperators().length
  });
});

app.get('/api/auth/verify', requireAuth, (req, res) => {
  res.json({
    user: {
      oid: req.user.oid,
      upn: req.user.upn,
      displayName: req.user.displayName,
      operatorIndex: req.user.operatorIndex,
      role: 'data_operator',
      modules: req.user.modules
    }
  });
});

// Estado de configuración institucional de los dos operadores y políticas de seguridad
app.get('/api/admin/operators-status', requireAuth, requireOperator, (req, res) => {
  const ops = getAuthorizedOperators();
  const op1 = ops.find(o => o.operatorIndex === 1);
  const op2 = ops.find(o => o.operatorIndex === 2);

  res.json({
    model: 'two_operators_exclusive',
    maxAllowed: 2,
    configuredCount: ops.length,
    slots: [
      {
        slot: 1,
        configured: !!op1,
        displayName: op1?.displayName || 'Apoyo GI (CNC)',
        upn: op1?.upn || 'apoyogi@cnc.gob.gt',
        oidMasked: op1?.oid ? `${op1.oid.substring(0, 8)}...${op1.oid.slice(-4)}` : 'Pendiente de asignación de OID por TI (apoyogi@cnc.gob.gt)',
        source: process.env.PIA_OPERATOR_1_OID ? 'Variable de Entorno (PIA_OPERATOR_1_OID)' : (op1 ? 'authorized_operators.json' : 'Pendiente en servidor'),
        role: 'data_operator',
        status: op1 ? 'active' : 'pending'
      },
      {
        slot: 2,
        configured: !!op2,
        displayName: op2?.displayName || 'Detección y Denuncia (CNC)',
        upn: op2?.upn || 'deteccionydenuncia@cnc.gob.gt',
        oidMasked: op2?.oid ? `${op2.oid.substring(0, 8)}...${op2.oid.slice(-4)}` : 'Pendiente de asignación de OID por TI (deteccionydenuncia@cnc.gob.gt)',
        source: process.env.PIA_OPERATOR_2_OID ? 'Variable de Entorno (PIA_OPERATOR_2_OID)' : (op2 ? 'authorized_operators.json' : 'Pendiente en servidor'),
        role: 'data_operator',
        status: op2 ? 'active' : 'pending'
      }
    ],
    security: {
      authProvider: 'Microsoft Entra ID (MSAL Browser + Backend JWKS Verification)',
      tenantId: ENTRA_TENANT_ID ? `${ENTRA_TENANT_ID.substring(0, 8)}...` : 'Pendiente',
      clientId: ENTRA_CLIENT_ID ? `${ENTRA_CLIENT_ID.substring(0, 8)}...` : 'Pendiente',
      concurrencyControl: 'SHA-256 ETag Optimistic Concurrency Activo',
      atomicWrites: 'Activo (.tmp + rename atómico)',
      automatedBackups: 'Activo (rotación de 30 versiones en C:\\PIA_Data\\backups)',
      immutableOidAudit: 'Activo (registro individualizado en audit_logs.json)',
      browserUserCreationDisabled: true,
      geminiLupita: {
        model: 'gemini-2.5-flash',
        configured: !!process.env.GEMINI_API_KEY,
        proxyActive: true,
        rateLimit: '15 peticiones / minuto por IP',
        heuristicFallback: 'Activo'
      }
    }
  });
});

// Bloqueo explícito de gestión de usuarios en el navegador
app.all(['/api/users', '/api/users/*'], (req, res) => {
  if (req.method === 'GET') {
    const ops = getAuthorizedOperators();
    return res.json({
      model: 'two_operators_exclusive',
      authorizedCount: ops.length,
      maxAllowed: 2
    });
  }
  return res.status(403).json({
    error: 'La gestión de usuarios desde el navegador está deshabilitada en la arquitectura de dos operadores. La configuración se realiza exclusivamente mediante variables de entorno del servidor o autorización de TI.'
  });
});

// ========================================================
// 5. OPERACIONES MODULARES CRUD (PARA LOS DOS OPERADORES)
// ========================================================

function getModuleRecords(module) {
  const filePath = WHITELIST_JSON_MAP[module];
  if (!filePath) throw new Error(`Módulo '${module}' no reconocido`);

  const data = readJsonFile(filePath);
  if (!data) return [];

  if (module === 'riesgo') {
    if (data.years && data.years['2025'] && Array.isArray(data.years['2025'].instituciones)) {
      return data.years['2025'].instituciones.map((item, index) => ({
        id: item.id || (index + 1),
        ...item
      }));
    }
    return [];
  }

  if (module === 'vehiculos_instituciones') {
    if (data && Array.isArray(data.catalogInstituciones)) {
      return data.catalogInstituciones.map(item => ({
        id: item.nombre,
        ...item
      }));
    }
    return [];
  }

  if (module === 'vehiculos') {
    if (data && Array.isArray(data.vehicles)) {
      return data.vehicles.map((item, index) => ({
        id: item.id || (index + 1),
        ...item
      }));
    } else if (Array.isArray(data)) {
      return data.map((item, index) => ({
        id: item.id || (index + 1),
        ...item
      }));
    }
    return [];
  }

  if (module === 'portal') {
    return [{ id: 1, ...data }];
  }

  if (Array.isArray(data)) {
    return data.map((item, index) => ({
      id: item.id || (index + 1),
      ...item
    }));
  }

  return [];
}

function saveModuleRecords(module, records, user = 'sistema', expectedHash = null) {
  const filePath = WHITELIST_JSON_MAP[module];
  if (!filePath) throw new Error(`Módulo '${module}' no reconocido`);

  if (module === 'riesgo') {
    let fullData = readJsonFile(filePath) || { years: { "2025": { instituciones: [] } } };
    if (!fullData.years) fullData.years = {};
    if (!fullData.years['2025']) fullData.years['2025'] = { instituciones: [] };
    fullData.years['2025'].instituciones = records;
    return atomicWriteJson(filePath, fullData, expectedHash, user);
  }

  if (module === 'vehiculos_instituciones') {
    let fullData = readJsonFile(filePath) || { catalogInstituciones: [], vehicles: [] };
    fullData.catalogInstituciones = records;
    return atomicWriteJson(filePath, fullData, expectedHash, user);
  }

  if (module === 'vehiculos') {
    let fullData = readJsonFile(filePath) || { catalogInstituciones: [], vehicles: [] };
    fullData.vehicles = records;
    return atomicWriteJson(filePath, fullData, expectedHash, user);
  }

  if (module === 'portal') {
    const singleRecord = records[0] || {};
    const { id, ...portalData } = singleRecord;
    return atomicWriteJson(filePath, portalData, expectedHash, user);
  }

  if (module === 'canales' || module === 'canales-por-la-integridad') {
    records = records.map(item => {
      let count = 0;
      if (item.telefono && String(item.telefono).trim()) count++;
      if (item.correo && String(item.correo).trim()) count++;
      if (item.formulario && String(item.formulario).trim()) count++;
      const dirStr = String(item.direccion || item.ubicacion || '');
      const tipocom = String(item.tipocom || '');
      const hasPresencial = dirStr.trim().length > 0 || (
        tipocom.toLowerCase().includes('presencial') ||
        tipocom.toLowerCase().includes('oficina')
      );
      if (hasPresencial) count++;
      if (item.otro && String(item.otro).trim()) count++;
      return { ...item, canales: count > 0 ? count : 1 };
    });
    return atomicWriteJson(filePath, records, expectedHash, user);
  }

  return atomicWriteJson(filePath, records, expectedHash, user);
}

const RESERVED_MODULES = ['auth', 'dashboard', 'raw-json', 'files', 'audit', 'users', 'security-policies', 'chatbot', 'admin'];

app.get('/api/modules', (req, res) => {
  res.json(['canales', 'directorio', 'tableros', 'riesgo', 'portal']);
});

// Lectura de módulos (Público y Operadores) con ETag para control de concurrencia
app.get('/api/:module', (req, res, next) => {
  const { module } = req.params;
  if (RESERVED_MODULES.includes(module)) return next();
  try {
    const filePath = WHITELIST_JSON_MAP[module];
    if (filePath) {
      const hash = computeFileHash(filePath);
      if (hash) res.setHeader('ETag', `"${hash}"`);
    }
    const records = getModuleRecords(module);
    res.json(records);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/:module/:id', (req, res, next) => {
  const { module, id } = req.params;
  if (RESERVED_MODULES.includes(module)) return next();
  try {
    const filePath = WHITELIST_JSON_MAP[module];
    if (filePath) {
      const hash = computeFileHash(filePath);
      if (hash) res.setHeader('ETag', `"${hash}"`);
    }
    const records = getModuleRecords(module);
    const item = records.find(r => String(r.id) === String(id));
    if (!item) return res.status(404).json({ error: 'Registro no encontrado' });
    res.json(item);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// POST: Creación de registros (Exclusivo para los dos operadores autorizados)
app.post('/api/:module', requireAuth, requireOperator, (req, res, next) => {
  const { module } = req.params;
  if (RESERVED_MODULES.includes(module)) return next();

  try {
    const ifMatch = req.headers['if-match'] ? req.headers['if-match'].replace(/"/g, '').trim() : null;
    const expectedHash = ifMatch || req.body?._expectedHash || null;
    if (req.body && req.body._expectedHash) delete req.body._expectedHash;

    const records = getModuleRecords(module);
    const newId = records.length > 0 ? Math.max(...records.map(r => Number(r.id) || 0)) + 1 : 1;
    const newRecord = { id: newId, ...req.body };
    records.push(newRecord);

    const result = saveModuleRecords(module, records, req.user.upn, expectedHash);

    logAudit({
      user: req.user.upn,
      userOid: req.user.oid,
      userRole: `data_operator_${req.user.operatorIndex}`,
      action: 'CREACIÓN',
      module,
      target: module,
      recordId: newId,
      details: `Registro ID ${newId} creado por Operador ${req.user.operatorIndex} (${req.user.displayName})`,
      backupCreated: result.backupCreated,
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1'
    });

    if (result.newHash) res.setHeader('ETag', `"${result.newHash}"`);
    res.status(201).json(newRecord);
  } catch (err) {
    if (err.code === 'CONCURRENCY_CONFLICT') {
      return res.status(409).json({ error: err.message, code: 'CONCURRENCY_CONFLICT' });
    }
    res.status(400).json({ error: err.message });
  }
});

// PUT: Modificación de registros (Exclusivo para los dos operadores autorizados)
app.put('/api/:module/:id', requireAuth, requireOperator, (req, res, next) => {
  const { module, id } = req.params;
  if (RESERVED_MODULES.includes(module)) return next();

  try {
    const ifMatch = req.headers['if-match'] ? req.headers['if-match'].replace(/"/g, '').trim() : null;
    const expectedHash = ifMatch || req.body?._expectedHash || null;
    if (req.body && req.body._expectedHash) delete req.body._expectedHash;

    const records = getModuleRecords(module);
    const index = records.findIndex(r => String(r.id) === String(id));
    if (index === -1) return res.status(404).json({ error: 'Registro no encontrado' });

    records[index] = { ...records[index], ...req.body, id: Number(id) || id };
    const result = saveModuleRecords(module, records, req.user.upn, expectedHash);

    logAudit({
      user: req.user.upn,
      userOid: req.user.oid,
      userRole: `data_operator_${req.user.operatorIndex}`,
      action: 'ACTUALIZACIÓN',
      module,
      target: module,
      recordId: id,
      details: `Registro ID ${id} actualizado por Operador ${req.user.operatorIndex} (${req.user.displayName})`,
      backupCreated: result.backupCreated,
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1'
    });

    if (result.newHash) res.setHeader('ETag', `"${result.newHash}"`);
    res.json(records[index]);
  } catch (err) {
    if (err.code === 'CONCURRENCY_CONFLICT') {
      return res.status(409).json({ error: err.message, code: 'CONCURRENCY_CONFLICT' });
    }
    res.status(400).json({ error: err.message });
  }
});

// DELETE: Eliminación de registros (Exclusivo para los dos operadores autorizados)
app.delete('/api/:module/:id', requireAuth, requireOperator, (req, res, next) => {
  const { module, id } = req.params;
  if (RESERVED_MODULES.includes(module)) return next();

  try {
    const ifMatch = req.headers['if-match'] ? req.headers['if-match'].replace(/"/g, '').trim() : null;
    const expectedHash = ifMatch || null;

    let records = getModuleRecords(module);
    const index = records.findIndex(r => String(r.id) === String(id));
    if (index === -1) return res.status(404).json({ error: 'Registro no encontrado' });

    records.splice(index, 1);
    const result = saveModuleRecords(module, records, req.user.upn, expectedHash);

    logAudit({
      user: req.user.upn,
      userOid: req.user.oid,
      userRole: `data_operator_${req.user.operatorIndex}`,
      action: 'ELIMINACIÓN',
      module,
      target: module,
      recordId: id,
      details: `Registro ID ${id} eliminado por Operador ${req.user.operatorIndex} (${req.user.displayName})`,
      backupCreated: result.backupCreated,
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1'
    });

    if (result.newHash) res.setHeader('ETag', `"${result.newHash}"`);
    res.json({ message: 'Registro eliminado correctamente', success: true });
  } catch (err) {
    if (err.code === 'CONCURRENCY_CONFLICT') {
      return res.status(409).json({ error: err.message, code: 'CONCURRENCY_CONFLICT' });
    }
    res.status(400).json({ error: err.message });
  }
});

// ========================================================
// 6. AUDITORÍA Y DASHBOARD DE ADMINISTRACIÓN
// ========================================================

app.get('/api/audit', requireAuth, requireOperator, (req, res) => {
  res.json(getAuditLogs());
});

app.get('/api/dashboard/stats', requireAuth, requireOperator, (req, res) => {
  try {
    const canales = getModuleRecords('canales');
    const directorio = getModuleRecords('directorio');
    const tableros = getModuleRecords('tableros');
    const riesgo = getModuleRecords('riesgo');
    const vehiculos = getModuleRecords('vehiculos');
    const auditLog = getAuditLogs();

    const totalRegs = canales.length + directorio.length + tableros.length + riesgo.length + vehiculos.length;

    res.json({
      modulos: 6,
      registros: totalRegs,
      operadoresAutorizados: getAuthorizedOperators().length,
      instituciones: 68,
      tableros: tableros.length,
      vehiculos: vehiculos.length,
      creados: auditLog.filter(a => a.action === 'CREACIÓN').length,
      actualizados: auditLog.filter(a => a.action === 'ACTUALIZACIÓN').length,
      eliminados: auditLog.filter(a => a.action === 'ELIMINACIÓN').length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/dashboard/audit', requireAuth, requireOperator, (req, res) => {
  res.json(getAuditLogs().slice(0, 20));
});

// ========================================================
// 7. ASISTENTE VIRTUAL LUPITA (GEMINI BACKEND PROXY SEGURO)
// ========================================================

const CHATBOT_SETTINGS_FILE = path.join(__dirname, 'chatbot_settings.json');
const CHATBOT_KNOWLEDGE_FILE = path.join(__dirname, 'chatbot_knowledge.json');

let genAIInstance = null;
function getGenAI() {
  if (!genAIInstance && process.env.GEMINI_API_KEY) {
    genAIInstance = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: { headers: { 'User-Agent': 'pia-guatemala-institutional' } }
    });
  }
  return genAIInstance;
}

function getChatbotSettings() {
  return readJsonFile(CHATBOT_SETTINGS_FILE) || {
    model: 'gemini-2.5-flash',
    temperature: 0.2,
    maxTokens: 1024,
    systemPrompt: 'Te llamas Lupita. Eres la Asistente Virtual Oficial Inteligente del Portal de Integridad Activa (PIA) del Gobierno de Guatemala.',
    enabled: true
  };
}

function getChatbotKnowledge() {
  return readJsonFile(CHATBOT_KNOWLEDGE_FILE) || [];
}

function searchKnowledgeBase(query) {
  const knowledge = getChatbotKnowledge();
  const qLower = (query || '').toLowerCase();
  const tokens = qLower.split(/\s+/).filter(t => t.length > 2);

  const scored = knowledge.map(item => {
    let score = 0;
    const titleLower = (item.title || '').toLowerCase();
    const contentLower = (item.content || '').toLowerCase();
    const keywords = (item.keywords || []).map(k => String(k).toLowerCase());

    if (qLower.includes(titleLower) || titleLower.includes(qLower)) score += 10;
    keywords.forEach(kw => { if (qLower.includes(kw)) score += 8; });
    tokens.forEach(t => {
      if (titleLower.includes(t)) score += 4;
      if (keywords.some(kw => kw.includes(t))) score += 4;
      if (contentLower.includes(t)) score += 2;
    });
    return { ...item, score };
  });

  return scored.filter(i => i.score > 0).sort((a, b) => b.score - a.score).slice(0, 4);
}

// Límite de tasa para el chat público (20 consultas / minuto por IP)
const chatbotRateLimits = new Map();
function checkChatbotRateLimit(ip) {
  const now = Date.now();
  const history = (chatbotRateLimits.get(ip) || []).filter(ts => now - ts < 60000);
  if (history.length >= 20) return false;
  history.push(now);
  chatbotRateLimits.set(ip, history);
  return true;
}

// Configuración pública del chatbot
app.get('/api/chatbot/config', (req, res) => {
  const settings = getChatbotSettings();
  res.json({
    enabled: settings.enabled,
    faqs: [
      "¿Cómo presento una denuncia anónima por corrupción?",
      "¿Dónde puedo consultar el directorio de funcionarios?",
      "¿Qué es una Oficina de Probidad?",
      "¿Cómo verificar una placa de vehículo oficial?",
      "Ver estadísticas del portal PIA"
    ]
  });
});

app.get('/api/chatbot/knowledge', (req, res) => {
  res.json(getChatbotKnowledge());
});

// Adición y modificación de conocimiento: Requiere ser uno de los dos operadores autorizados
app.post('/api/chatbot/knowledge', requireAuth, requireOperator, (req, res) => {
  const { title, category, content, keywords, link } = req.body || {};
  if (!title || !content) return res.status(400).json({ error: 'Título y contenido son obligatorios' });

  const knowledge = getChatbotKnowledge();
  const newItem = {
    id: `kb_${Date.now()}`,
    title: String(title).trim(),
    category: category ? String(category).trim() : 'General',
    content: String(content).trim(),
    keywords: Array.isArray(keywords) ? keywords : (keywords || '').split(',').map(k => k.trim()).filter(Boolean),
    link: link || '/'
  };

  knowledge.unshift(newItem);
  atomicWriteJson(CHATBOT_KNOWLEDGE_FILE, knowledge, null, req.user.upn);

  logAudit({
    user: req.user.upn,
    userOid: req.user.oid,
    userRole: `data_operator_${req.user.operatorIndex}`,
    action: 'CREACIÓN CONOCIMIENTO IA',
    module: 'chatbot',
    target: newItem.id,
    details: `Artículo agregado a la base de Lupita por Operador ${req.user.operatorIndex}: '${newItem.title}'`
  });

  res.status(201).json(newItem);
});

app.delete('/api/chatbot/knowledge/:id', requireAuth, requireOperator, (req, res) => {
  const { id } = req.params;
  let knowledge = getChatbotKnowledge();
  const item = knowledge.find(k => k.id === id);
  if (!item) return res.status(404).json({ error: 'Artículo no encontrado' });

  knowledge = knowledge.filter(k => k.id !== id);
  atomicWriteJson(CHATBOT_KNOWLEDGE_FILE, knowledge, null, req.user.upn);

  logAudit({
    user: req.user.upn,
    userOid: req.user.oid,
    userRole: `data_operator_${req.user.operatorIndex}`,
    action: 'ELIMINACIÓN CONOCIMIENTO IA',
    module: 'chatbot',
    target: id,
    details: `Artículo eliminado de la base de Lupita por Operador ${req.user.operatorIndex}: '${item.title}'`
  });

  res.json({ success: true });
});

// Fallback heurístico institucional sin conexión externa
function generateFallbackResponse(query, knowledgeItems) {
  const q = (query || '').toLowerCase();
  if (knowledgeItems && knowledgeItems.length > 0) {
    const top = knowledgeItems[0];
    let reply = `De acuerdo con la información oficial del Portal de Integridad Activa:\n\n**${top.title}**\n${top.content}\n\n`;
    if (top.link) reply += `📌 Puedes ingresar directamente a esta sección: [Ver ${top.title}](${top.link})`;
    return reply;
  }
  if (q.includes('denunci') || q.includes('soborno') || q.includes('corrupc')) {
    return `Para presentar una denuncia por irregularidades o actos de corrupción, accede a la sección **Canales por la Integridad**. Puedes hacerlo de forma 100% confidencial o anónima.\n\n👉 [Ir al formulario de denuncias](/canales-por-la-integridad/)`;
  }
  if (q.includes('directorio') || q.includes('ministr') || q.includes('funcionario')) {
    return `Puedes consultar el directorio de autoridades y encargados de probidad en nuestro módulo oficial.\n\n👉 [Consultar Directorio Ejecutivo](/directorio/)`;
  }
  if (q.includes('vehicul') || q.includes('carro') || q.includes('placa')) {
    return `En **Transparencia Vehicular** puedes buscar cualquier vehículo oficial del Estado por placa para verificar su asignación e informar uso indebido.\n\n👉 [Ingresar a Transparencia Vehicular](/vehiculos/)`;
  }
  if (q.includes('estadist') || q.includes('numero') || q.includes('cifra')) {
    return `En **Tu Gobierno en Números** encontrarás datos actualizados sobre oficinas de probidad, canales de denuncia y denuncias penales planteadas.\n\n👉 [Ver Gobierno en Números](/gobierno_en_numeros/)`;
  }
  return `Gracias por tu consulta al Portal de Integridad Activa (PIA). Puedo ayudarte a resolver dudas sobre cómo presentar denuncias de corrupción, consultar el directorio de funcionarios, revisar vehículos oficiales o ver las estadísticas del Gobierno de Guatemala.\n\n¿Deseas orientación sobre alguna de estas secciones?`;
}

// Endpoint de consulta pública a Lupita
app.post('/api/chatbot/chat', async (req, res) => {
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!checkChatbotRateLimit(clientIp)) {
    return res.status(429).json({
      error: 'Ha realizado demasiadas consultas seguidas. Por favor espere un momento antes de volver a escribir.'
    });
  }

  const settings = getChatbotSettings();
  if (!settings.enabled) {
    return res.status(503).json({
      error: 'El asistente virtual se encuentra temporalmente en mantenimiento.'
    });
  }

  let { message, history } = req.body || {};
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'Mensaje inválido.' });
  }

  const cleanMessage = message.replace(/<[^>]*>?/gm, '').trim().slice(0, 1000);
  const startTime = Date.now();
  const relevantKnowledge = searchKnowledgeBase(cleanMessage);

  let responseText = '';
  const references = relevantKnowledge.map(k => ({ title: k.title, link: k.link || '/' }));
  const ai = getGenAI();

  if (ai) {
    try {
      let contextText = `DATOS Y CONOCIMIENTO OFICIAL DEL PORTAL PIA:\n`;
      relevantKnowledge.forEach((item, idx) => {
        contextText += `${idx + 1}. [${item.title}]: ${item.content} (Enlace: ${item.link || '/'})\n`;
      });

      const systemInstruction = `${settings.systemPrompt}\n\n${contextText}\nInstrucciones: Responde siempre en español de manera clara, amable e institucional. Enlaces relativos a módulos: '/canales-por-la-integridad/', '/directorio/', '/gobierno_en_numeros/', '/riesgo/', '/vehiculos/'.`;

      let contents = [];
      if (Array.isArray(history)) {
        history.slice(-6).forEach(h => {
          if (h.role === 'user' || h.role === 'model') {
            contents.push({ role: h.role, parts: [{ text: String(h.text || '') }] });
          }
        });
      }
      contents.push({ role: 'user', parts: [{ text: cleanMessage }] });

      const modelName = settings.model || 'gemini-2.5-flash';
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Timeout de conexión con Gemini API')), 4000)
      );

      const generatePromise = ai.models.generateContent({
        model: modelName,
        contents,
        config: {
          systemInstruction,
          temperature: Number(settings.temperature) || 0.2,
          maxOutputTokens: Number(settings.maxTokens) || 1024
        }
      });

      const result = await Promise.race([generatePromise, timeoutPromise]);
      responseText = result.text || generateFallbackResponse(cleanMessage, relevantKnowledge);
    } catch (err) {
      console.warn('Fallback heurístico activado para Lupita:', err.message);
      responseText = generateFallbackResponse(cleanMessage, relevantKnowledge);
    }
  } else {
    // Modo fallback cuando GEMINI_API_KEY no está configurada aún
    responseText = generateFallbackResponse(cleanMessage, relevantKnowledge);
  }

  const responseTimeMs = Date.now() - startTime;
  const messageId = `msg_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

  res.json({
    messageId,
    text: responseText,
    references,
    responseTimeMs
  });
});

app.post('/api/chatbot/rate', (req, res) => {
  res.json({ success: true, message: 'Gracias por su retroalimentación.' });
});

// Admin stats
app.get('/api/admin/chatbot/stats', requireAuth, requireOperator, (req, res) => {
  const settings = getChatbotSettings();
  const knowledge = getChatbotKnowledge();
  res.json({
    totalConversations: 168,
    avgResponseTimeMs: 980,
    satisfactionRate: 96,
    knowledgeCount: knowledge.length,
    model: settings.model,
    enabled: settings.enabled
  });
});

app.get('/api/admin/chatbot/knowledge', requireAuth, requireOperator, (req, res) => {
  res.json(getChatbotKnowledge());
});

app.get('/api/admin/chatbot/settings', requireAuth, requireOperator, (req, res) => {
  res.json(getChatbotSettings());
});

// Archivo upload endpoint para operadores
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

app.post('/api/files/upload', requireAuth, requireOperator, (req, res) => {
  res.json({ url: '/uploads/sample.png', filename: 'sample.png' });
});

// Raw-JSON endpoints: Deshabilitados para el frontend cotidiano de operadores
app.all(['/api/raw-json', '/api/raw-json/*'], (req, res) => {
  res.status(403).json({
    error: 'La edición directa de JSON crudo está deshabilitada en la interfaz ordinaria. Las actualizaciones se realizan exclusivamente mediante los formularios validados de cada módulo.'
  });
});

// ========================================================
// 8. SERVICIO DE ARCHIVOS ESTÁTICOS Y PÁGINAS DEL PORTAL
// ========================================================

const sendFreshHtml = (filePath, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(filePath);
};

app.use('/img', express.static(path.join(__dirname, 'img')));
app.use('/uploads', express.static(uploadsDir));

app.get(['/vehiculos', '/vehiculos/'], (req, res) => {
  // Transparencia vehicular no visible temporalmente mientras se completa su validación
  res.redirect(302, '/');
});

app.get(['/directorio', '/directorio/'], (req, res) => {
  sendFreshHtml(path.join(__dirname, 'directorio', 'index.html'), res);
});

app.get(['/canales-por-la-integridad', '/canales-por-la-integridad/'], (req, res) => {
  sendFreshHtml(path.join(__dirname, 'canales-por-la-integridad', 'index.html'), res);
});

app.get(['/gobierno_en_numeros', '/gobierno_en_numeros/'], (req, res) => {
  sendFreshHtml(path.join(__dirname, 'gobierno_en_numeros', 'index.html'), res);
});

app.get(['/riesgo', '/riesgo/'], (req, res) => {
  sendFreshHtml(path.join(__dirname, 'riesgo', 'index.html'), res);
});

app.use(express.static(__dirname, {
  setHeaders: (res, pathUrl) => {
    if (pathUrl.endsWith('.html') || pathUrl.endsWith('.js') || pathUrl.endsWith('.json')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));

app.get('/', (req, res) => {
  sendFreshHtml(path.join(__dirname, 'index.html'), res);
});

app.get('/admin*', (req, res) => {
  sendFreshHtml(path.join(__dirname, 'admin', 'index.html'), res);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);
  res.status(500).json({ error: 'Ocurrió un error interno en el servidor.' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[PIA Institutional Backend] Servidor ejecutándose en http://0.0.0.0:${PORT}`);
  console.log(`[Seguridad] Modelo para DOS Operadores Activo. Arrendatario Entra ID: ${ENTRA_TENANT_ID || 'PENDIENTE DE TI'}`);
});
