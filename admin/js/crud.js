// crud.js - Operaciones CRUD con control de concurrencia optimista (ETag)

const API_BASE = getApiBase();
const moduleETags = {};

async function getModules() {
    const res = await fetch(`${API_BASE}/modules`, { headers: getHeaders() });
    if (!res.ok) throw new Error('Error al obtener módulos');
    return res.json();
}

async function getModuleData(module) {
    const res = await fetch(`${API_BASE}/${module}`, { headers: getHeaders() });
    if (!res.ok) throw new Error(`Error al obtener datos de ${module}`);
    const etag = res.headers.get('ETag');
    if (etag) moduleETags[module] = etag;
    return res.json();
}

async function getRecord(module, id) {
    const res = await fetch(`${API_BASE}/${module}/${id}`, { headers: getHeaders() });
    if (!res.ok) throw new Error('Registro no encontrado');
    const etag = res.headers.get('ETag');
    if (etag) moduleETags[module] = etag;
    return res.json();
}

async function createRecord(module, data) {
    const headers = getHeaders();
    if (moduleETags[module]) headers['If-Match'] = moduleETags[module];

    const res = await fetch(`${API_BASE}/${module}`, {
        method: 'POST',
        headers,
        body: JSON.stringify(data)
    });
    if (!res.ok) {
        const err = await res.json();
        if (res.status === 409) {
            throw new Error(err.error || 'Conflicto de concurrencia: Los datos fueron modificados por la otra persona operadora. Por favor recargue la tabla.');
        }
        throw new Error(err.error || 'Error al crear');
    }
    const newEtag = res.headers.get('ETag');
    if (newEtag) moduleETags[module] = newEtag;
    return res.json();
}

async function updateRecord(module, id, data) {
    const headers = getHeaders();
    if (moduleETags[module]) headers['If-Match'] = moduleETags[module];

    const res = await fetch(`${API_BASE}/${module}/${id}`, {
        method: 'PUT',
        headers,
        body: JSON.stringify(data)
    });
    if (!res.ok) {
        const err = await res.json();
        if (res.status === 409) {
            throw new Error(err.error || 'Conflicto de concurrencia: Los datos fueron modificados por la otra persona operadora. Por favor recargue la tabla.');
        }
        throw new Error(err.error || 'Error al actualizar');
    }
    const newEtag = res.headers.get('ETag');
    if (newEtag) moduleETags[module] = newEtag;
    return res.json();
}

async function deleteRecord(module, id) {
    const headers = getHeaders();
    if (moduleETags[module]) headers['If-Match'] = moduleETags[module];

    const res = await fetch(`${API_BASE}/${module}/${id}`, {
        method: 'DELETE',
        headers
    });
    if (!res.ok) {
        const err = await res.json();
        if (res.status === 409) {
            throw new Error(err.error || 'Conflicto de concurrencia: Los datos fueron modificados por la otra persona operadora. Por favor recargue la tabla.');
        }
        throw new Error(err.error || 'Error al eliminar');
    }
    const newEtag = res.headers.get('ETag');
    if (newEtag) moduleETags[module] = newEtag;
    return res.json();
}