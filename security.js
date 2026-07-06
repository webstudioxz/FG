// ============================================================
// security.js - Sistema de Seguridad Blindado con Detección Inteligente
// ============================================================

const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const crypto = require('crypto');

// Archivos de seguridad
const ATAQUES_FILE = path.join(__dirname, 'ataques.json');
const BLOQUEOS_SEGURIDAD_FILE = path.join(__dirname, 'bloqueos-seguridad.json');
const IP_CONFIANZA_FILE = path.join(__dirname, 'ip-confianza.json');

// Variables en memoria
let ataquesMemoria = [];
let bloqueosMemoria = {};
let intentosLogin = new Map();
let ipConfianza = {};

// Rangos de IPs de operadores móviles (ejemplos - se puede ampliar)
const RANGOS_MOVILES = {
    // Cuba
    'CUB': ['179.0.0.0/8', '190.0.0.0/8', '200.0.0.0/8'],
    // Argentina
    'ARG': ['181.0.0.0/8', '186.0.0.0/8', '190.0.0.0/8'],
    // México
    'MEX': ['187.0.0.0/8', '189.0.0.0/8', '200.0.0.0/8'],
    // Colombia
    'COL': ['181.0.0.0/8', '186.0.0.0/8', '190.0.0.0/8'],
    // Chile
    'CHL': ['181.0.0.0/8', '186.0.0.0/8', '190.0.0.0/8'],
    // Perú
    'PER': ['181.0.0.0/8', '186.0.0.0/8', '190.0.0.0/8'],
    // España
    'ESP': ['185.0.0.0/8', '188.0.0.0/8', '193.0.0.0/8'],
    // EE.UU.
    'USA': ['192.0.0.0/8', '198.0.0.0/8', '204.0.0.0/8'],
    // Global
    'GLOBAL': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
};

// ============================================================
// INICIALIZACIÓN
// ============================================================
async function initSecurityFiles() {
    try {
        // Crear archivos si no existen
        if (!fsSync.existsSync(ATAQUES_FILE)) {
            await fs.writeFile(ATAQUES_FILE, JSON.stringify([], null, 2));
        }
        if (!fsSync.existsSync(BLOQUEOS_SEGURIDAD_FILE)) {
            await fs.writeFile(BLOQUEOS_SEGURIDAD_FILE, JSON.stringify({}, null, 2));
        }
        if (!fsSync.existsSync(IP_CONFIANZA_FILE)) {
            await fs.writeFile(IP_CONFIANZA_FILE, JSON.stringify({}, null, 2));
        }
        
        // Cargar datos en memoria
        const ataquesData = await fs.readFile(ATAQUES_FILE, 'utf8');
        ataquesMemoria = JSON.parse(ataquesData);
        
        const bloqueosData = await fs.readFile(BLOQUEOS_SEGURIDAD_FILE, 'utf8');
        bloqueosMemoria = JSON.parse(bloqueosData);
        
        const confianzaData = await fs.readFile(IP_CONFIANZA_FILE, 'utf8');
        ipConfianza = JSON.parse(confianzaData);
        
        console.log(`🛡️ Sistema de seguridad blindado iniciado`);
        console.log(`📊 Ataques registrados: ${ataquesMemoria.length}`);
        console.log(`🚫 IPs bloqueadas: ${Object.keys(bloqueosMemoria).length}`);
        console.log(`✅ IPs con confianza: ${Object.keys(ipConfianza).length}`);
    } catch (e) {
        console.error('❌ Error inicializando sistema de seguridad:', e);
    }
}

// ============================================================
// FUNCIONES UTILITARIAS
// ============================================================
function generarId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2) + require('crypto').randomBytes(4).toString('hex');
}

function formatearTiempoRestante(ms) {
    if (ms <= 0) return 'Expirado';
    const horas = Math.floor(ms / 3600000);
    const minutos = Math.floor((ms % 3600000) / 60000);
    if (horas > 0) {
        return `${horas}h ${minutos}m`;
    }
    return `${minutos}m`;
}

// ============================================================
// DETECCIÓN INTELIGENTE DE VPN vs DATOS MÓVILES
// ============================================================

// Verificar si una IP está en un rango de datos móviles
function esIPMovil(ip) {
    // Si es localhost, no es móvil
    if (ip === 'localhost' || ip === '127.0.0.1' || ip === '::1') {
        return false;
    }
    
    // Verificar contra rangos conocidos de operadores móviles
    for (const [pais, rangos] of Object.entries(RANGOS_MOVILES)) {
        for (const rango of rangos) {
            if (ipEnRango(ip, rango)) {
                return true;
            }
        }
    }
    
    return false;
}

// Verificar si una IP está dentro de un rango CIDR
function ipEnRango(ip, rangoCIDR) {
    try {
        const [rango, mascara] = rangoCIDR.split('/');
        const mascaraInt = parseInt(mascara);
        
        // Convertir IP a número
        const ipPartes = ip.split('.');
        if (ipPartes.length !== 4) return false;
        const ipNum = (parseInt(ipPartes[0]) << 24) |
                     (parseInt(ipPartes[1]) << 16) |
                     (parseInt(ipPartes[2]) << 8) |
                     parseInt(ipPartes[3]);
        
        // Convertir rango a número
        const rangoPartes = rango.split('.');
        if (rangoPartes.length !== 4) return false;
        const rangoNum = (parseInt(rangoPartes[0]) << 24) |
                        (parseInt(rangoPartes[1]) << 16) |
                        (parseInt(rangoPartes[2]) << 8) |
                        parseInt(rangoPartes[3]);
        
        // Calcular máscara
        const mascaraNum = ~((1 << (32 - mascaraInt)) - 1);
        
        // Verificar si está en el rango
        return (ipNum & mascaraNum) === (rangoNum & mascaraNum);
    } catch (e) {
        return false;
    }
}

// Verificar si una IP es de VPN/Proxy usando detección heurística
async function esVPN(ip) {
    try {
        // 1. Verificar en lista negra de VPNs conocidas
        const vpnIPs = await obtenerVPNListaNegra();
        if (vpnIPs.includes(ip)) {
            return true;
        }
        
        // 2. Verificar características de VPN
        // Las VPNs suelen usar ciertos rangos de IPs
        const rangosVPN = [
            '103.0.0.0/8', '104.0.0.0/8', '107.0.0.0/8', '108.0.0.0/8',
            '109.0.0.0/8', '110.0.0.0/8', '111.0.0.0/8', '112.0.0.0/8',
            '113.0.0.0/8', '114.0.0.0/8', '115.0.0.0/8', '116.0.0.0/8',
            '117.0.0.0/8', '118.0.0.0/8', '119.0.0.0/8', '120.0.0.0/8'
        ];
        
        for (const rango of rangosVPN) {
            if (ipEnRango(ip, rango)) {
                return true;
            }
        }
        
        // 3. Verificar si la IP tiene características de VPN
        // Las VPNs suelen tener latencia alta y puertos específicos
        // Esto requeriría análisis adicional en tiempo real
        
        return false;
    } catch (e) {
        console.error('Error verificando VPN:', e);
        return false;
    }
}

// Obtener lista negra de VPNs (simulada - en producción usar API externa)
async function obtenerVPNListaNegra() {
    try {
        // Aquí se podría consultar una API externa como:
        // - ip-api.com
        // - ipinfo.io
        // - vpnapi.io
        // Por ahora devolvemos una lista simulada
        return [
            '104.16.0.0', '104.17.0.0', '104.18.0.0', '104.19.0.0',
            '104.20.0.0', '104.21.0.0', '104.22.0.0', '104.23.0.0',
            '104.24.0.0', '104.25.0.0', '104.26.0.0', '104.27.0.0'
        ];
    } catch (e) {
        return [];
    }
}

// Obtener IP del cliente de forma segura
function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    let ip = forwarded ? forwarded.split(',')[0] : req.socket.remoteAddress;
    ip = ip.replace('::ffff:', '');
    if (ip === '127.0.0.1' || ip === '::1') {
        ip = 'localhost';
    }
    return ip;
}

// ============================================================
// SISTEMA DE CONFIANZA PARA IPs
// ============================================================

// Verificar si una IP tiene confianza alta
async function tieneConfianzaAlta(ip) {
    try {
        if (ip === 'localhost') return true;
        
        const datos = ipConfianza[ip];
        if (!datos) return false;
        
        // Si la IP ha estado activa por más de 7 días y tiene menos de 3 incidentes
        const antiguedad = Date.now() - new Date(datos.primerVista).getTime();
        const confiable = antiguedad > 7 * 24 * 60 * 60 * 1000 && 
                          (datos.incidentes || 0) < 3;
        
        return confiable;
    } catch (e) {
        return false;
    }
}

// Registrar actividad de IP (para construir confianza)
async function registrarActividadIP(ip, req) {
    try {
        if (ip === 'localhost') return;
        
        if (!ipConfianza[ip]) {
            ipConfianza[ip] = {
                primerVista: new Date().toISOString(),
                ultimaVista: new Date().toISOString(),
                incidentes: 0,
                visitas: 0,
                esMovil: esIPMovil(ip),
                esVPN: await esVPN(ip)
            };
        } else {
            ipConfianza[ip].ultimaVista = new Date().toISOString();
            ipConfianza[ip].visitas = (ipConfianza[ip].visitas || 0) + 1;
        }
        
        // Guardar cada 100 visitas para no saturar el disco
        if (Object.keys(ipConfianza).length % 100 === 0) {
            await guardarConfianza();
        }
    } catch (e) {
        console.error('Error registrando actividad IP:', e);
    }
}

// Incrementar incidentes de una IP
async function incrementarIncidentes(ip) {
    try {
        if (ip === 'localhost') return;
        
        if (!ipConfianza[ip]) {
            ipConfianza[ip] = {
                primerVista: new Date().toISOString(),
                ultimaVista: new Date().toISOString(),
                incidentes: 1,
                visitas: 1,
                esMovil: esIPMovil(ip),
                esVPN: await esVPN(ip)
            };
        } else {
            ipConfianza[ip].incidentes = (ipConfianza[ip].incidentes || 0) + 1;
        }
        
        await guardarConfianza();
    } catch (e) {
        console.error('Error incrementando incidentes:', e);
    }
}

// Guardar datos de confianza
async function guardarConfianza() {
    try {
        await fs.writeFile(IP_CONFIANZA_FILE, JSON.stringify(ipConfianza, null, 2));
    } catch (e) {
        console.error('Error guardando confianza:', e);
    }
}

// ============================================================
// SISTEMA DE BLOQUEO CON INTELIGENCIA
// ============================================================

// Verificar si una IP está bloqueada (con excepciones para móviles)
async function isIPBlocked(ip) {
    try {
        if (ip === 'localhost') return { bloqueado: false };
        
        const bloqueo = bloqueosMemoria[ip];
        if (!bloqueo) return { bloqueado: false };
        
        // Si la IP es de datos móviles y tiene confianza alta, darle una oportunidad
        const esMovil = await esIPMovil(ip);
        const confianzaAlta = await tieneConfianzaAlta(ip);
        
        if (esMovil && confianzaAlta && !bloqueo.permanente) {
            // Usuario móvil con confianza: reducir tiempo de bloqueo a la mitad
            const tiempoRestante = bloqueo.expiracion - Date.now();
            const nuevoTiempo = Math.floor(tiempoRestante * 0.5);
            bloqueo.expiracion = Date.now() + nuevoTiempo;
            await guardarBloqueos();
        }
        
        if (bloqueo.permanente) {
            // Para bloqueos permanentes, verificar si es un error
            if (esMovil && confianzaAlta) {
                // Usuario móvil con confianza: convertir a temporal
                bloqueo.permanente = false;
                bloqueo.expiracion = Date.now() + 60 * 60 * 1000; // 1 hora
                await guardarBloqueos();
                return { 
                    bloqueado: true, 
                    permanente: false, 
                    tiempoRestante: 60 * 60 * 1000,
                    motivo: 'Bloqueo convertido a temporal por confianza',
                    conteo: bloqueo.conteo
                };
            }
            
            return { 
                bloqueado: true, 
                permanente: true, 
                motivo: bloqueo.motivo,
                conteo: bloqueo.conteo
            };
        }
        
        if (Date.now() < bloqueo.expiracion) {
            return { 
                bloqueado: true, 
                permanente: false, 
                tiempoRestante: bloqueo.expiracion - Date.now(),
                motivo: bloqueo.motivo,
                conteo: bloqueo.conteo
            };
        } else {
            // Bloqueo expirado, eliminar
            delete bloqueosMemoria[ip];
            await guardarBloqueos();
            return { bloqueado: false };
        }
    } catch (e) {
        console.error('Error verificando bloqueo de IP:', e);
        return { bloqueado: false };
    }
}

// Registrar un ataque (con ajustes para móviles)
async function registrarAtaque(ip, tipo, detalles, usuario = null, path = null) {
    try {
        // Si la IP es móvil y tiene confianza, registrar pero no bloquear inmediatamente
        const esMovil = await esIPMovil(ip);
        const confianzaAlta = await tieneConfianzaAlta(ip);
        
        if (esMovil && confianzaAlta) {
            // Para usuarios móviles confiables, solo registrar y dar advertencia
            const ataque = {
                id: generarId(),
                ip: ip,
                tipo: tipo,
                detalles: detalles + ' (USUARIO MÓVIL - ADVERTENCIA)',
                usuario: usuario,
                path: path || 'unknown',
                fecha: new Date().toISOString(),
                resuelto: false,
                esMovil: true,
                esAdvertencia: true
            };
            
            ataquesMemoria.push(ataque);
            await guardarAtaques();
            await incrementarIncidentes(ip);
            
            return ataque;
        }
        
        // Para IPs normales, registro completo
        const ataque = {
            id: generarId(),
            ip: ip,
            tipo: tipo,
            detalles: detalles,
            usuario: usuario,
            path: path || 'unknown',
            fecha: new Date().toISOString(),
            resuelto: false,
            esMovil: esMovil,
            esAdvertencia: false
        };
        
        ataquesMemoria.push(ataque);
        await guardarAtaques();
        
        return ataque;
    } catch (e) {
        console.error('Error registrando ataque:', e);
        return null;
    }
}

// Bloquear IP con sistema adaptativo
async function bloquearIP(ip, motivo, tipoAtaque, usuario = null, path = null) {
    try {
        if (ip === 'localhost') {
            console.warn('⚠️ Intento de bloquear localhost ignorado');
            return null;
        }
        
        // Verificar si es IP móvil
        const esMovil = await esIPMovil(ip);
        const confianzaAlta = await tieneConfianzaAlta(ip);
        
        // Obtener conteo de bloqueos previos
        let conteo = 0;
        if (bloqueosMemoria[ip]) {
            conteo = bloqueosMemoria[ip].conteo || 0;
        }
        
        conteo++;
        
        // Sistema adaptativo:
        // - IPs móviles con confianza: 2 veces más intentos antes de bloquear
        // - IPs normales: sistema estándar
        let limiteBloqueos = 3;
        if (esMovil && confianzaAlta) {
            limiteBloqueos = 6; // 6 intentos para móviles confiables
        }
        
        if (conteo >= limiteBloqueos) {
            // Bloqueo permanente solo para ataques confirmados
            if (tipoAtaque === 'SQL_INJECTION' || 
                tipoAtaque === 'XSS_ATTACK' || 
                tipoAtaque === 'COMMAND_INJECTION') {
                // Ataques graves: bloqueo permanente
                const bloqueo = {
                    ip: ip,
                    conteo: conteo,
                    motivo: motivo,
                    tipoAtaque: tipoAtaque,
                    usuario: usuario,
                    path: path,
                    permanente: true,
                    expiracion: null,
                    fechaBloqueo: new Date().toISOString(),
                    esMovil: esMovil
                };
                
                bloqueosMemoria[ip] = bloqueo;
                await guardarBloqueos();
                
                return {
                    ip: ip,
                    conteo: conteo,
                    permanente: true,
                    duracionTexto: 'PERMANENTE',
                    motivo: motivo
                };
            } else {
                // Para otros ataques, bloqueo temporal más largo
                const duracion = esMovil && confianzaAlta ? 
                    2 * 60 * 60 * 1000 : // 2 horas para móviles
                    24 * 60 * 60 * 1000; // 24 horas para normales
                
                const bloqueo = {
                    ip: ip,
                    conteo: conteo,
                    motivo: motivo,
                    tipoAtaque: tipoAtaque,
                    usuario: usuario,
                    path: path,
                    permanente: false,
                    expiracion: Date.now() + duracion,
                    fechaBloqueo: new Date().toISOString(),
                    esMovil: esMovil
                };
                
                bloqueosMemoria[ip] = bloqueo;
                await guardarBloqueos();
                
                return {
                    ip: ip,
                    conteo: conteo,
                    permanente: false,
                    duracionTexto: `${duracion / (60 * 60 * 1000)} horas`,
                    motivo: motivo
                };
            }
        }
        
        // Bloqueo temporal estándar
        let duracion = 0;
        if (esMovil && confianzaAlta) {
            duracion = 30 * 60 * 1000; // 30 minutos para móviles confiables
        } else {
            duracion = conteo * 60 * 60 * 1000; // 1h, 2h para normales
        }
        
        const bloqueo = {
            ip: ip,
            conteo: conteo,
            motivo: motivo,
            tipoAtaque: tipoAtaque,
            usuario: usuario,
            path: path,
            permanente: false,
            expiracion: Date.now() + duracion,
            fechaBloqueo: new Date().toISOString(),
            esMovil: esMovil
        };
        
        bloqueosMemoria[ip] = bloqueo;
        await guardarBloqueos();
        
        const duracionTexto = esMovil && confianzaAlta ? 
            '30 minutos' : 
            `${conteo} hora${conteo > 1 ? 's' : ''}`;
        
        return {
            ip: ip,
            conteo: conteo,
            permanente: false,
            duracionTexto: duracionTexto,
            motivo: motivo
        };
    } catch (e) {
        console.error('Error bloqueando IP:', e);
        return null;
    }
}

// Desbloquear una IP
async function desbloquearIP(ip) {
    try {
        if (bloqueosMemoria[ip]) {
            delete bloqueosMemoria[ip];
            await guardarBloqueos();
            return true;
        }
        return false;
    } catch (e) {
        console.error('Error desbloqueando IP:', e);
        return false;
    }
}

// Guardar ataques en archivo
async function guardarAtaques() {
    try {
        await fs.writeFile(ATAQUES_FILE, JSON.stringify(ataquesMemoria, null, 2));
    } catch (e) {
        console.error('Error guardando ataques:', e);
    }
}

// Guardar bloqueos en archivo
async function guardarBloqueos() {
    try {
        await fs.writeFile(BLOQUEOS_SEGURIDAD_FILE, JSON.stringify(bloqueosMemoria, null, 2));
    } catch (e) {
        console.error('Error guardando bloqueos:', e);
    }
}

// ============================================================
// DETECTORES DE ATAQUES (MEJORADOS)
// ============================================================

// Detectar SQL Injection
function detectarSQLInjection(valor) {
    if (typeof valor !== 'string') return false;
    const patrones = [
        /(\bUNION\b\s+\bALL\b|\bUNION\b)/i,
        /(\bSELECT\b.*\bFROM\b)/i,
        /(\bINSERT\b.*\bINTO\b)/i,
        /(\bUPDATE\b.*\bSET\b)/i,
        /(\bDELETE\b.*\bFROM\b)/i,
        /(\bDROP\b.*\bTABLE\b|\bDROP\b.*\bDATABASE\b)/i,
        /(\bALTER\b.*\bTABLE\b)/i,
        /(\bCREATE\b.*\bTABLE\b)/i,
        /(\bEXEC\b|\bEXECUTE\b)/i,
        /--/,
        /;/,
        /(\bOR\b\s+1\s*=\s*1)/i,
        /(\bOR\b\s+1\s*=\s*2)/i,
        /(\bAND\b\s+1\s*=\s*1)/i,
        /(\bAND\b\s+1\s*=\s*2)/i,
        /('.*\bOR\b.*'=')/i,
        /(\bSLEEP\b\s*\()/i,
        /(\bBENCHMARK\b\s*\()/i
    ];
    for (const patron of patrones) {
        if (patron.test(valor)) {
            return true;
        }
    }
    return false;
}

// Detectar XSS
function detectarXSS(valor) {
    if (typeof valor !== 'string') return false;
    const patrones = [
        /<script/i,
        /javascript:/i,
        /onerror\s*=/i,
        /onload\s*=/i,
        /onclick\s*=/i,
        /onmouseover\s*=/i,
        /onmouseout\s*=/i,
        /onfocus\s*=/i,
        /onblur\s*=/i,
        /onchange\s*=/i,
        /onsubmit\s*=/i,
        /onreset\s*=/i,
        /onselect\s*=/i,
        /onkeydown\s*=/i,
        /onkeyup\s*=/i,
        /onkeypress\s*=/i,
        /alert\s*\(/i,
        /prompt\s*\(/i,
        /confirm\s*\(/i,
        /document\.cookie/i,
        /document\.location/i,
        /window\.location/i,
        /eval\s*\(/i,
        /setTimeout\s*\(/i,
        /setInterval\s*\(/i,
        /Function\s*\(/i
    ];
    for (const patron of patrones) {
        if (patron.test(valor)) {
            return true;
        }
    }
    return false;
}

// Detectar Path Traversal
function detectarPathTraversal(valor) {
    if (typeof valor !== 'string') return false;
    const patrones = [
        /\.\.\//,
        /\.\.\\/,
        /%2e%2e%2f/,
        /%2e%2e%5c/,
        /\.\.\/\.\./,
        /\.\.\\\.\./,
        /\/etc\/passwd/,
        /\/windows\/win\.ini/,
        /\/var\/log/,
        /\/root\//,
        /\/boot\//
    ];
    for (const patron of patrones) {
        if (patron.test(valor)) {
            return true;
        }
    }
    return false;
}

// Detectar comandos del sistema
function detectarCommandInjection(valor) {
    if (typeof valor !== 'string') return false;
    const patrones = [
        /;.*/,
        /\|.*/,
        /&.*/,
        /`.*`/,
        /\$\s*\(/,
        /\$(.*\))/,
        /rm\s+-rf/i,
        /wget\s+/i,
        /curl\s+/i,
        /nc\s+/i,
        /ncat\s+/i,
        /telnet\s+/i,
        /ssh\s+/i,
        /scp\s+/i,
        /sftp\s+/i,
        /ftp\s+/i,
        /chmod\s+/i,
        /chown\s+/i,
        /kill\s+/i,
        /pkill\s+/i,
        /system\s*\(/i,
        /exec\s*\(/i,
        /shell_exec\s*\(/i,
        /passthru\s*\(/i,
        /popen\s*\(/i,
        /proc_open\s*\(/i
    ];
    for (const patron of patrones) {
        if (patron.test(valor)) {
            return true;
        }
    }
    return false;
}

// ============================================================
// MIDDLEWARE DE SEGURIDAD CON DETECCIÓN INTELIGENTE
// ============================================================

async function seguridadMiddleware(req, res, next) {
    const ip = getClientIP(req);
    const path = req.path;
    const metodo = req.method;
    const userAgent = req.headers['user-agent'] || 'unknown';
    
    // Registrar actividad de la IP (para construir confianza)
    await registrarActividadIP(ip, req);
    
    // Verificar si es IP móvil para ajustar políticas
    const esMovil = await esIPMovil(ip);
    const confianzaAlta = await tieneConfianzaAlta(ip);
    
    // 1. Verificar si la IP está bloqueada (con excepciones)
    const estadoBloqueo = await isIPBlocked(ip);
    
    if (estadoBloqueo.bloqueado) {
        const tiempoTexto = estadoBloqueo.permanente ? 
            'PERMANENTE' : 
            formatearTiempoRestante(estadoBloqueo.tiempoRestante);
        
        // Si es móvil y confiable, pero bloqueado, dar una oportunidad
        if (esMovil && confianzaAlta && !estadoBloqueo.permanente) {
            // Reducir tiempo de bloqueo a la mitad
            const nuevoTiempo = Math.floor(estadoBloqueo.tiempoRestante * 0.5);
            if (bloqueosMemoria[ip]) {
                bloqueosMemoria[ip].expiracion = Date.now() + nuevoTiempo;
                await guardarBloqueos();
            }
        }
        
        console.warn(`🚫 ACCESO DENEGADO - IP bloqueada: ${ip} - Motivo: ${estadoBloqueo.motivo} - Tiempo: ${tiempoTexto}`);
        
        return res.status(403).json({
            error: '🚫 Acceso denegado por razones de seguridad',
            codigo: 'SEC-403',
            motivo: estadoBloqueo.motivo,
            permanente: estadoBloqueo.permanente,
            tiempoRestante: tiempoTexto,
            ip: ip
        });
    }
    
    // 2. Detectar bots maliciosos (User-Agent)
    const botPatterns = /(bot|crawler|spider|scraper|curl|wget|python|perl|ruby|java|php|go|node|nikto|nmap|sqlmap|havij|acunetix|netsparker|burp|zap|dirbuster|gobuster|wfuzz|hydra|medusa|ncrack|xerxes|slowloris|hulk|goldeneye|ddos|attack|malicious|scanner|exploit|payload)/i;
    if (botPatterns.test(userAgent)) {
        await registrarAtaque(ip, 'BOT_DETECTED', `Bot malicioso detectado: ${userAgent}`, null, path);
    }
    
    // 3. Recolectar todos los parámetros
    const parametros = { ...req.body, ...req.query, ...req.params };
    
    // 4. Analizar cada parámetro en busca de ataques
    for (const [key, value] of Object.entries(parametros)) {
        if (typeof value === 'string') {
            // 4.1 Detectar SQL Injection
            if (detectarSQLInjection(value)) {
                console.warn(`⚠️ SQL Injection detectado - IP: ${ip} - Path: ${path} - Parámetro: ${key}=${value}`);
                await registrarAtaque(ip, 'SQL_INJECTION', `Intento de inyección SQL en ${path} - Parámetro: ${key}=${value}`, null, path);
                
                // Si es móvil y confiable, dar advertencia en lugar de bloquear
                if (esMovil && confianzaAlta) {
                    await incrementarIncidentes(ip);
                    return res.status(403).json({
                        error: '⚠️ Actividad sospechosa detectada. Por favor, verifica tus datos.',
                        codigo: 'SEC-403-SQL-WARN',
                        ip: ip,
                        esAdvertencia: true,
                        incidentes: ipConfianza[ip]?.incidentes || 1
                    });
                }
                
                const resultado = await bloquearIP(ip, `Intento de inyección SQL detectado en ${path}`, 'SQL_INJECTION', null, path);
                return res.status(403).json({
                    error: '🚫 Actividad sospechosa detectada',
                    codigo: 'SEC-403-SQL',
                    ip: ip,
                    motivo: 'Intento de inyección SQL'
                });
            }
            
            // 4.2 Detectar XSS
            if (detectarXSS(value)) {
                console.warn(`⚠️ XSS detectado - IP: ${ip} - Path: ${path} - Parámetro: ${key}=${value}`);
                await registrarAtaque(ip, 'XSS_ATTACK', `Intento de XSS en ${path} - Parámetro: ${key}=${value}`, null, path);
                
                if (esMovil && confianzaAlta) {
                    await incrementarIncidentes(ip);
                    return res.status(403).json({
                        error: '⚠️ Actividad sospechosa detectada. Por favor, verifica tus datos.',
                        codigo: 'SEC-403-XSS-WARN',
                        ip: ip,
                        esAdvertencia: true,
                        incidentes: ipConfianza[ip]?.incidentes || 1
                    });
                }
                
                const resultado = await bloquearIP(ip, `Intento de XSS detectado en ${path}`, 'XSS_ATTACK', null, path);
                return res.status(403).json({
                    error: '🚫 Actividad sospechosa detectada',
                    codigo: 'SEC-403-XSS',
                    ip: ip,
                    motivo: 'Intento de XSS'
                });
            }
            
            // 4.3 Detectar Path Traversal
            if (detectarPathTraversal(value)) {
                console.warn(`⚠️ Path Traversal detectado - IP: ${ip} - Path: ${path} - Parámetro: ${key}=${value}`);
                await registrarAtaque(ip, 'PATH_TRAVERSAL', `Intento de Path Traversal en ${path} - Parámetro: ${key}=${value}`, null, path);
                
                if (esMovil && confianzaAlta) {
                    await incrementarIncidentes(ip);
                    return res.status(403).json({
                        error: '⚠️ Actividad sospechosa detectada. Por favor, verifica tus datos.',
                        codigo: 'SEC-403-PATH-WARN',
                        ip: ip,
                        esAdvertencia: true,
                        incidentes: ipConfianza[ip]?.incidentes || 1
                    });
                }
                
                const resultado = await bloquearIP(ip, `Intento de Path Traversal detectado en ${path}`, 'PATH_TRAVERSAL', null, path);
                return res.status(403).json({
                    error: '🚫 Actividad sospechosa detectada',
                    codigo: 'SEC-403-PATH',
                    ip: ip,
                    motivo: 'Intento de Path Traversal'
                });
            }
            
            // 4.4 Detectar Command Injection
            if (detectarCommandInjection(value)) {
                console.warn(`⚠️ Command Injection detectado - IP: ${ip} - Path: ${path} - Parámetro: ${key}=${value}`);
                await registrarAtaque(ip, 'COMMAND_INJECTION', `Intento de Command Injection en ${path} - Parámetro: ${key}=${value}`, null, path);
                
                if (esMovil && confianzaAlta) {
                    await incrementarIncidentes(ip);
                    return res.status(403).json({
                        error: '⚠️ Actividad sospechosa detectada. Por favor, verifica tus datos.',
                        codigo: 'SEC-403-CMD-WARN',
                        ip: ip,
                        esAdvertencia: true,
                        incidentes: ipConfianza[ip]?.incidentes || 1
                    });
                }
                
                const resultado = await bloquearIP(ip, `Intento de Command Injection detectado en ${path}`, 'COMMAND_INJECTION', null, path);
                return res.status(403).json({
                    error: '🚫 Actividad sospechosa detectada',
                    codigo: 'SEC-403-CMD',
                    ip: ip,
                    motivo: 'Intento de Command Injection'
                });
            }
        }
    }
    
    // 5. Headers de seguridad
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Todo está bien, continuar
    next();
}

// ============================================================
// FUNCIONES DE CONTROL DE FUERZA BRUTA
// ============================================================

function obtenerIntentosLogin(ip) {
    const ahora = Date.now();
    const ventana = 5 * 60 * 1000;
    
    if (!intentosLogin.has(ip)) {
        intentosLogin.set(ip, { intentos: 0, primerIntento: ahora });
    }
    
    const datos = intentosLogin.get(ip);
    
    if (ahora - datos.primerIntento > ventana) {
        intentosLogin.set(ip, { intentos: 0, primerIntento: ahora });
        return 0;
    }
    
    return datos.intentos;
}

function incrementarIntentosLogin(ip) {
    const ahora = Date.now();
    const ventana = 5 * 60 * 1000;
    
    if (!intentosLogin.has(ip)) {
        intentosLogin.set(ip, { intentos: 1, primerIntento: ahora });
        return 1;
    }
    
    const datos = intentosLogin.get(ip);
    
    if (ahora - datos.primerIntento > ventana) {
        intentosLogin.set(ip, { intentos: 1, primerIntento: ahora });
        return 1;
    }
    
    datos.intentos++;
    return datos.intentos;
}

// ============================================================
// RUTAS DE SEGURIDAD PARA ADMIN (con información de móvil)
// ============================================================

// Obtener todos los ataques registrados
async function getAtaques(req, res) {
    try {
        const ataquesFormateados = ataquesMemoria.map(a => ({
            ...a,
            fechaFormateada: new Date(a.fecha).toLocaleString(),
            tipoClase: getTipoAtaqueClase(a.tipo),
            esMovilTexto: a.esMovil ? '📱 Móvil' : '💻 Fijo'
        }));
        res.json(ataquesFormateados);
    } catch (e) {
        console.error('Error cargando ataques:', e);
        res.json([]);
    }
}

// Obtener IPs bloqueadas
async function getBloqueos(req, res) {
    try {
        const bloqueosFormateados = Object.entries(bloqueosMemoria).map(([ip, info]) => ({
            ip: ip,
            ...info,
            tiempoRestanteFormateado: info.permanente ? 
                'PERMANENTE' : 
                info.expiracion ? 
                    formatearTiempoRestante(info.expiracion - Date.now()) : 
                    'Expirado',
            fechaBloqueoFormateada: new Date(info.fechaBloqueo).toLocaleString(),
            esMovilTexto: info.esMovil ? '📱 Móvil' : '💻 Fijo'
        }));
        res.json(bloqueosFormateados);
    } catch (e) {
        console.error('Error cargando bloqueos:', e);
        res.json([]);
    }
}

// Desbloquear IP desde admin
async function desbloquearIPAdmin(req, res) {
    try {
        const ip = req.params.ip;
        const exito = await desbloquearIP(ip);
        if (exito) {
            console.log(`✅ IP desbloqueada manualmente: ${ip}`);
            res.json({ success: true, message: 'IP desbloqueada correctamente' });
        } else {
            res.status(404).json({ error: 'IP no encontrada en la lista de bloqueos' });
        }
    } catch (e) {
        console.error('Error desbloqueando IP:', e);
        res.status(500).json({ error: 'Error al desbloquear IP' });
    }
}

// Bloquear IP manualmente desde admin
async function bloquearIPAdmin(req, res) {
    try {
        const { ip, motivo, permanente } = req.body;
        if (!ip) {
            return res.status(400).json({ error: 'IP requerida' });
        }
        
        if (ip === 'localhost') {
            return res.status(400).json({ error: 'No se puede bloquear localhost' });
        }
        
        if (permanente) {
            const bloqueo = await bloquearIP(ip, motivo || 'Bloqueado manualmente por admin (PERMANENTE)', 'ADMIN_MANUAL');
            return res.json({ success: true, bloqueo });
        }
        
        const bloqueo = await bloquearIP(ip, motivo || 'Bloqueado manualmente por admin', 'ADMIN_MANUAL');
        res.json({ success: true, bloqueo });
    } catch (e) {
        console.error('Error bloqueando IP manualmente:', e);
        res.status(500).json({ error: 'Error al bloquear IP' });
    }
}

// Marcar ataque como resuelto
async function resolverAtaque(req, res) {
    try {
        const id = req.params.id;
        const index = ataquesMemoria.findIndex(a => a.id === id);
        if (index === -1) {
            return res.status(404).json({ error: 'Ataque no encontrado' });
        }
        
        ataquesMemoria[index].resuelto = true;
        await guardarAtaques();
        res.json({ success: true });
    } catch (e) {
        console.error('Error resolviendo ataque:', e);
        res.status(500).json({ error: 'Error al resolver ataque' });
    }
}

// Eliminar ataque (admin)
async function eliminarAtaque(req, res) {
    try {
        const id = req.params.id;
        const index = ataquesMemoria.findIndex(a => a.id === id);
        if (index === -1) {
            return res.status(404).json({ error: 'Ataque no encontrado' });
        }
        
        ataquesMemoria.splice(index, 1);
        await guardarAtaques();
        res.json({ success: true });
    } catch (e) {
        console.error('Error eliminando ataque:', e);
        res.status(500).json({ error: 'Error al eliminar ataque' });
    }
}

// Obtener estadísticas de seguridad
async function getEstadisticasSeguridad(req, res) {
    try {
        const totalAtaques = ataquesMemoria.length;
        const ataquesNoResueltos = ataquesMemoria.filter(a => !a.resuelto).length;
        const totalBloqueos = Object.keys(bloqueosMemoria).length;
        const bloqueosPermanentes = Object.values(bloqueosMemoria).filter(b => b.permanente).length;
        const bloqueosMoviles = Object.values(bloqueosMemoria).filter(b => b.esMovil).length;
        
        const tiposAtaque = {};
        for (const a of ataquesMemoria) {
            tiposAtaque[a.tipo] = (tiposAtaque[a.tipo] || 0) + 1;
        }
        
        // IPs con confianza alta
        const ipsConfianza = Object.keys(ipConfianza).filter(ip => 
            ipConfianza[ip] && 
            (ipConfianza[ip].incidentes || 0) < 3 &&
            Date.now() - new Date(ipConfianza[ip].primerVista).getTime() > 7 * 24 * 60 * 60 * 1000
        ).length;
        
        res.json({
            totalAtaques,
            ataquesNoResueltos,
            totalBloqueos,
            bloqueosPermanentes,
            bloqueosMoviles,
            ipsConfianza,
            tiposAtaque,
            topIPsAtacantes: getTopIPsAtacantes(5)
        });
    } catch (e) {
        console.error('Error obteniendo estadísticas:', e);
        res.status(500).json({ error: 'Error al obtener estadísticas' });
    }
}

// Obtener top IPs atacantes
function getTopIPsAtacantes(limite = 5) {
    const ipCount = {};
    for (const a of ataquesMemoria) {
        ipCount[a.ip] = (ipCount[a.ip] || 0) + 1;
    }
    return Object.entries(ipCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, limite)
        .map(([ip, count]) => ({ ip, count }));
}

// Obtener clase CSS para tipo de ataque
function getTipoAtaqueClase(tipo) {
    const clases = {
        'SQL_INJECTION': 'tag-danger',
        'XSS_ATTACK': 'tag-danger',
        'COMMAND_INJECTION': 'tag-danger',
        'PATH_TRAVERSAL': 'tag-danger',
        'BRUTE_FORCE': 'tag-warning',
        'BRUTE_FORCE_ATTEMPT': 'tag-warning',
        'BOT_DETECTED': 'tag-info',
        'ADMIN_MANUAL': 'tag-purple',
        'DIRECTORY_SCAN': 'tag-warning',
        'DESCONOCIDO': 'tag-warning'
    };
    return clases[tipo] || 'tag-warning';
}

// ============================================================
// EXPORTAR EL SISTEMA DE SEGURIDAD
// ============================================================

module.exports = {
    // Inicialización
    initSecurityFiles,
    
    // Middleware principal
    seguridadMiddleware,
    
    // Funciones de seguridad
    getClientIP,
    isIPBlocked,
    registrarAtaque,
    bloquearIP,
    desbloquearIP,
    
    // Detección inteligente
    esIPMovil,
    esVPN,
    tieneConfianzaAlta,
    registrarActividadIP,
    incrementarIncidentes,
    
    // Control de fuerza bruta
    obtenerIntentosLogin,
    incrementarIntentosLogin,
    
    // Rutas para admin
    getAtaques,
    getBloqueos,
    desbloquearIPAdmin,
    bloquearIPAdmin,
    resolverAtaque,
    eliminarAtaque,
    getEstadisticasSeguridad,
    
    // Datos en memoria
    ataquesMemoria,
    bloqueosMemoria,
    intentosLogin,
    ipConfianza
};