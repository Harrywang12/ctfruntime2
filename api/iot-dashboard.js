// Vercel Serverless Function
// SDG 9 Medium: IoT Dashboard
// Parameter pollution vulnerability: if device_id appears twice in the query
// string (e.g. ?device_id=sensor-1&device_id=admin), Node/Express will treat
// it as an array. The code checks `device_id[0]` for authorization but uses
// `device_id[device_id.length-1]` for the actual lookup, allowing access to
// the "admin" device which carries the proof.

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

        const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'iot-dashboard' });

        // Get ALL device_id values (URLSearchParams.getAll returns an array)
        const deviceIds = url.searchParams.getAll('device_id');

        if (deviceIds.length === 0) {
            // No device specified: return list of public sensors
            const sensors = [];
            for (let i = 0; i < 5; i++) {
                sensors.push({
                    device_id: `sensor-${i + 1}`,
                    type: ['temperature', 'humidity', 'pressure', 'vibration', 'airflow'][i],
                    value: (20 + simpleHash(seed, `val:${i}`) % 60).toFixed(1),
                    unit: ['°C', '%RH', 'bar', 'mm/s', 'm³/h'][i],
                    status: 'online',
                });
            }
            return json(res, 200, {
                ok: true,
                hint: 'Specify ?device_id=sensor-1 to view a specific device. Admin devices exist but are restricted.',
                devices: sensors,
                admin_note: 'Admin devices hold calibration secrets. Access requires the "admin" device_id, but the system blocks direct requests to it.',
            });
        }

        // VULNERABILITY: Authorization check uses the FIRST device_id
        const authCheck = deviceIds[0];
        // But the actual lookup uses the LAST device_id
        const lookupId = deviceIds[deviceIds.length - 1];

        // Block direct "admin" access
        if (authCheck === 'admin') {
            return json(res, 403, {
                error: 'Access to admin device is restricted.',
                hint: 'The system checks authorization on one parameter but may look up another. What if device_id appears more than once?',
            });
        }

        // Regular sensor lookup
        if (lookupId !== 'admin') {
            const sensorNum = parseInt(lookupId.replace('sensor-', ''), 10) || 1;
            return json(res, 200, {
                ok: true,
                device: {
                    device_id: lookupId,
                    type: ['temperature', 'humidity', 'pressure', 'vibration', 'airflow'][(sensorNum - 1) % 5],
                    value: (20 + simpleHash(seed, `val:${sensorNum}`) % 60).toFixed(1),
                    status: 'online',
                },
            });
        }

        // Admin device accessed via parameter pollution
        return json(res, 200, {
            ok: true,
            device: {
                device_id: 'admin',
                type: 'calibration_controller',
                status: 'restricted',
                calibration_secret: proof,
                message: 'Full calibration data exposed. This device should not be accessible.',
            },
        });
    } catch (e) {
        const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
        return json(res, 500, { error: msg });
    }
};
