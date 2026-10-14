// auth.js - Autenticación Institucional Microsoft Entra ID (Microsoft 365)

const API_BASE = getApiBase();
let msalAppInstance = null;
let entraConfigCache = null;

async function getEntraConfig() {
    if (entraConfigCache) return entraConfigCache;
    try {
        const res = await fetch(`${API_BASE}/auth/entra-config`);
        if (!res.ok) throw new Error('Error al consultar configuración institucional');
        entraConfigCache = await res.json();
        return entraConfigCache;
    } catch (e) {
        console.error('Error cargando entra-config:', e);
        return { configured: false };
    }
}

async function initMsal() {
    const config = await getEntraConfig();
    if (!config || !config.configured) {
        return null;
    }

    if (!window.msal) {
        console.error('La librería Microsoft MSAL Browser no está cargada.');
        return null;
    }

    if (!msalAppInstance) {
        const msalConfig = {
            auth: {
                clientId: config.clientId,
                authority: config.authority,
                redirectUri: config.redirectUri || (window.location.origin + '/admin/')
            },
            cache: {
                cacheLocation: 'sessionStorage',
                storeAuthStateInCookie: false
            }
        };
        msalAppInstance = new window.msal.PublicClientApplication(msalConfig);
        await msalAppInstance.initialize();
    }
    return msalAppInstance;
}

// Iniciar sesión con Microsoft 365 / Entra ID
async function loginWithEntra() {
    const config = await getEntraConfig();
    if (!config || !config.configured) {
        throw new Error('El servidor requiere configurar ENTRA_TENANT_ID y ENTRA_CLIENT_ID para el acceso institucional.');
    }

    const msalInstance = await initMsal();
    if (!msalInstance) {
        throw new Error('No fue posible inicializar el cliente de autenticación institucional.');
    }

    const loginRequest = {
        scopes: ['openid', 'profile', 'email']
    };

    let authResult;
    try {
        authResult = await msalInstance.loginPopup(loginRequest);
    } catch (err) {
        if (err.name === 'BrowserAuthError' || err.message?.includes('popup')) {
            // Fallback a redirect si popups están bloqueados
            return msalInstance.loginRedirect(loginRequest);
        }
        throw new Error('Error de autenticación con Microsoft: ' + (err.message || 'Proceso cancelado'));
    }

    const idToken = authResult.idToken;
    if (!idToken) {
        throw new Error('No se recibió un token de identidad válido de Microsoft Entra ID.');
    }

    // Validar token y rol directamente con el backend
    const verified = await verifyToken(idToken);
    localStorage.setItem('token', idToken);
    sessionStorage.setItem('token', idToken);
    return { token: idToken, user: verified.user };
}

// Verificar validez del token en el backend
async function verifyToken(token) {
    const res = await fetch(`${API_BASE}/auth/verify`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Token institucional inválido o usuario sin rol asignado.');
    }

    const data = await res.json();
    if (data.user) {
        localStorage.setItem('user', JSON.stringify(data.user));
    }
    return data;
}

function logout(reason) {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    sessionStorage.removeItem('token');
    sessionStorage.removeItem('user');
    if (reason) {
        sessionStorage.setItem('logout_reason', reason);
    }
    window.location.reload();
}

// Exportar al ámbito global
window.loginWithEntra = loginWithEntra;
window.getEntraConfig = getEntraConfig;
window.verifyToken = verifyToken;
window.logout = logout;