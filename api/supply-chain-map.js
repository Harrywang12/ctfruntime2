
const { computeProof } = require('./_runtimeCrypto');

function simpleHash(seed, salt) {
    const str = String(seed) + String(salt);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash);
}

function json(res, status, body) {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify(body));
}

module.exports = async function handler(req, res) {
    try {
        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        const seed = url.searchParams.get('seed') || '';

        if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
            return json(res, 400, { error: 'Missing or invalid seed' });
        }

        const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'supply-chain-map' });

        const cities = ['Lagos', 'Mumbai', 'São Paulo', 'Jakarta', 'Nairobi', 'Dhaka', 'Cairo', 'Lima'];
        const materials = ['Steel', 'Copper', 'Cement', 'Silicon', 'Aluminum', 'Fiber Optic Cable'];

        const routes = [];
        for (let i = 0; i < 6; i++) {
            const from = cities[simpleHash(seed, `from:${i}`) % cities.length];
            let to = cities[simpleHash(seed, `to:${i}`) % cities.length];
            if (to === from) to = cities[(simpleHash(seed, `to:${i}`) + 1) % cities.length];

            routes.push({
                route_id: `SCR-${(1000 + simpleHash(seed, `rid:${i}`) % 9000)}`,
                origin: from,
                destination: to,
                material: materials[simpleHash(seed, `mat:${i}`) % materials.length],
                status: 'active',
                tonnage: 50 + simpleHash(seed, `ton:${i}`) % 950,
            });
        }

        // The classified route: contains the proof in a nested object
        routes.push({
            route_id: `SCR-${(1000 + simpleHash(seed, 'classified') % 9000)}`,
            origin: 'CLASSIFIED',
            destination: 'CLASSIFIED',
            material: 'CLASSIFIED',
            status: 'classified',
            tonnage: null,
            _metadata: {
                classification: 'INTERNAL',
                reason: 'Route under investigation for infrastructure violations',
                audit_code: proof,
            },
        });

        return json(res, 200, {
            ok: true,
            hint: 'The map only renders active routes. Are all routes active?',
            total_routes: routes.length,
            routes,
        });
    } catch (e) {
        const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
        return json(res, 500, { error: msg });
    }
};
