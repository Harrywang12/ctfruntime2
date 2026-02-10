// Vercel Serverless Function
// SDG 9 Medium: Drone Flight Path
// Prototype pollution vulnerability: the API accepts a JSON flight plan body
// and merges it into the drone state object using a naive deep merge.
// If the user sends "__proto__": { "isAdmin": true } in the flight plan,
// it pollutes Object.prototype and the subsequent admin check passes,
// revealing the proof.

const { computeProof } = require('./_runtimeCrypto');

function json(res, status, body) {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify(body));
}

// Intentionally vulnerable deep merge
function deepMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (
            source[key] &&
            typeof source[key] === 'object' &&
            !Array.isArray(source[key])
        ) {
            if (!target[key] || typeof target[key] !== 'object') {
                target[key] = {};
            }
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', (chunk) => { data += chunk; });
        req.on('end', () => {
            try {
                resolve(data ? JSON.parse(data) : {});
            } catch (e) {
                reject(new Error('Invalid JSON body'));
            }
        });
        req.on('error', reject);
    });
}

module.exports = async function handler(req, res) {
    try {
        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        const seed = url.searchParams.get('seed') || '';

        if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
            return json(res, 400, { error: 'Missing or invalid seed' });
        }

        const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'drone-flight-path' });

        if (req.method === 'GET') {
            return json(res, 200, {
                ok: true,
                system: 'SDG9 Drone Fleet Controller',
                message: 'Submit a flight plan via POST to register a delivery route.',
                example_body: {
                    drone_id: 'DRN-001',
                    waypoints: [
                        { lat: 6.5244, lng: 3.3792, alt: 120 },
                        { lat: 6.4541, lng: 3.3947, alt: 150 },
                    ],
                    priority: 'normal',
                },
                hint: 'Flight plans are merged into the drone state object. What happens if you send unexpected keys?',
                admin_note: 'Admin-level flight plans can access restricted corridors. The isAdmin flag is checked on the drone state object.',
            });
        }

        if (req.method !== 'POST') {
            return json(res, 405, { error: `Method ${req.method} not allowed` });
        }

        const body = await readBody(req);

        // Create a fresh drone state object
        const droneState = Object.create(null); // Clean prototype
        // Actually, for the vuln to work, we need a normal object:
        const state = {
            drone_id: 'DRN-UNASSIGNED',
            waypoints: [],
            priority: 'normal',
            isAdmin: false,
        };

        // Vulnerable merge: allows __proto__ pollution
        deepMerge(state, body);

        // Check admin privilege (pollutable via __proto__)
        if (state.isAdmin === true) {
            return json(res, 200, {
                ok: true,
                access: 'ADMIN',
                message: 'Admin corridor access granted. Restricted flight data follows.',
                restricted: {
                    corridor: 'SDG9-PRIORITY-LANE',
                    clearance_token: proof,
                    max_altitude_m: 500,
                },
                flight_plan: {
                    drone_id: state.drone_id,
                    waypoints: Array.isArray(state.waypoints) ? state.waypoints.length : 0,
                    priority: state.priority,
                },
            });
        }

        return json(res, 200, {
            ok: true,
            access: 'STANDARD',
            message: 'Flight plan registered. Standard corridors only.',
            flight_plan: {
                drone_id: state.drone_id,
                waypoints: Array.isArray(state.waypoints) ? state.waypoints.length : 0,
                priority: state.priority,
            },
            hint: 'Admin flights have additional data. How is isAdmin determined?',
        });
    } catch (e) {
        const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
        return json(res, 500, { error: msg });
    }
};
