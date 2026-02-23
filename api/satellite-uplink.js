
const { computeProof } = require('./_runtimeCrypto');

function json(res, status, body) {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify(body));
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', (chunk) => { data += chunk; });
        req.on('end', () => {
            try {
                resolve(data ? JSON.parse(data) : {});
            } catch {
                resolve({});
            }
        });
        req.on('error', reject);
    });
}

function computeChecksum(bytes) {
    let sum = 0;
    for (const b of bytes) {
        sum = (sum + b) & 0xFFFF;
    }
    return sum;
}

function buildSamplePacket() {
    // Build a sample "query" packet for documentation
    const magic = Buffer.from('SAT9', 'ascii');      // 4 bytes
    const version = Buffer.from([0x01]);              // 1 byte
    const cmd = Buffer.from([0x01]);                  // 1 byte: query
    const payload = Buffer.from('PING', 'ascii');     // 4 bytes
    const payloadLen = Buffer.alloc(2);
    payloadLen.writeUInt16BE(payload.length);          // 2 bytes

    const preChecksum = Buffer.concat([magic, version, cmd, payloadLen, payload]);
    const checksumVal = computeChecksum(preChecksum);
    const checksumBuf = Buffer.alloc(2);
    checksumBuf.writeUInt16BE(checksumVal);

    return Buffer.concat([preChecksum, checksumBuf]).toString('hex');
}

module.exports = async function handler(req, res) {
    try {
        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        const seed = url.searchParams.get('seed') || '';
        const action = url.searchParams.get('action') || 'info';

        if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
            return json(res, 400, { error: 'Missing or invalid seed' });
        }

        const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'satellite-uplink' });

        if (action === 'info') {
            return json(res, 200, {
                ok: true,
                system: 'SDG9 Satellite Uplink Terminal v2.0',
                protocol_spec: {
                    format: 'Binary packet, hex-encoded',
                    structure: [
                        { field: 'MAGIC', size: '4 bytes', value: 'ASCII "SAT9" (0x53415439)' },
                        { field: 'VERSION', size: '1 byte', value: '0x01' },
                        { field: 'CMD', size: '1 byte', value: '0x01=query, 0x42=admin_dump' },
                        { field: 'PAYLOAD_LEN', size: '2 bytes', value: 'Big-endian uint16, length of PAYLOAD' },
                        { field: 'PAYLOAD', size: 'variable', value: 'ASCII string' },
                        { field: 'CHECKSUM', size: '2 bytes', value: 'Big-endian uint16: sum of all preceding bytes mod 65536' },
                    ],
                    commands: {
                        '0x01': 'Query uplink status (any payload)',
                        '0x42': 'Admin dump (payload must contain authorization string)',
                    },
                },
                sample_packet: buildSamplePacket(),
                sample_description: 'A query packet with payload "PING"',
                hint: 'Craft a packet with CMD=0x42 and the correct authorization payload. The checksum must be valid.',
                submit: 'POST ?seed=<seed>&action=send with body { "packet": "<hex>" }',
            });
        }

        if (action === 'send') {
            if (req.method !== 'POST') {
                return json(res, 405, { error: 'Send action requires POST' });
            }

            const body = await readBody(req);
            const packetHex = (body.packet || '').trim().toLowerCase();

            if (!packetHex || !/^[0-9a-f]+$/.test(packetHex)) {
                return json(res, 400, { error: 'Missing or invalid hex packet in body' });
            }

            const packet = Buffer.from(packetHex, 'hex');

            // Minimum: 4 (magic) + 1 (ver) + 1 (cmd) + 2 (len) + 0 (payload) + 2 (checksum) = 10
            if (packet.length < 10) {
                return json(res, 400, { error: 'Packet too short. Minimum 10 bytes.' });
            }

            // Parse magic
            const magic = packet.slice(0, 4).toString('ascii');
            if (magic !== 'SAT9') {
                return json(res, 400, { error: `Invalid magic: expected "SAT9", got "${magic}"` });
            }

            // Parse version
            const version = packet[4];
            if (version !== 0x01) {
                return json(res, 400, { error: `Unsupported version: 0x${version.toString(16).padStart(2, '0')}` });
            }

            // Parse command
            const cmd = packet[5];

            // Parse payload length
            const payloadLen = packet.readUInt16BE(6);

            // Verify packet size
            const expectedLen = 4 + 1 + 1 + 2 + payloadLen + 2;
            if (packet.length !== expectedLen) {
                return json(res, 400, {
                    error: `Packet length mismatch. Header says payload=${payloadLen} bytes, expected total=${expectedLen}, got ${packet.length}`,
                });
            }

            // Parse payload
            const payload = packet.slice(8, 8 + payloadLen).toString('ascii');

            // Verify checksum
            const preChecksum = packet.slice(0, 8 + payloadLen);
            const expectedChecksum = computeChecksum(preChecksum);
            const receivedChecksum = packet.readUInt16BE(8 + payloadLen);

            if (expectedChecksum !== receivedChecksum) {
                return json(res, 400, {
                    error: 'Checksum mismatch',
                    expected: `0x${expectedChecksum.toString(16).padStart(4, '0')}`,
                    received: `0x${receivedChecksum.toString(16).padStart(4, '0')}`,
                    hint: 'Checksum is the sum of all bytes before the checksum field, mod 65536.',
                });
            }

            // Handle commands
            if (cmd === 0x01) {
                return json(res, 200, {
                    ok: true,
                    command: 'query',
                    response: {
                        uplink_status: 'connected',
                        signal_dbm: -67,
                        orbit_pass: 'LEO-4',
                        next_window_s: 342,
                    },
                });
            }

            if (cmd === 0x42) {
                // Admin dump requires specific payload
                if (!payload.includes('GRANT_ACCESS')) {
                    return json(res, 403, {
                        error: 'Admin dump denied: payload does not contain the required authorization string.',
                        hint: 'The payload for CMD 0x42 must contain "GRANT_ACCESS".',
                    });
                }

                return json(res, 200, {
                    ok: true,
                    command: 'admin_dump',
                    response: {
                        access_level: 'ADMIN',
                        satellite_id: 'SDG9-SAT-' + seed.slice(0, 6).toUpperCase(),
                        telemetry_key: proof,
                        orbit_data: {
                            altitude_km: 408,
                            inclination_deg: 51.6,
                            period_min: 92.7,
                        },
                    },
                });
            }

            return json(res, 400, { error: `Unknown command: 0x${cmd.toString(16).padStart(2, '0')}` });
        }

        return json(res, 400, { error: 'Unknown action. Use info or send.' });
    } catch (e) {
        const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
        return json(res, 500, { error: msg });
    }
};
