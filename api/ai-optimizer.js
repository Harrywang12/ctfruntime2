// Vercel Serverless Function
// SDG 9 Hard: AI Optimizer
// Multi-layered challenge:
// 1. The API exposes a "neural network inference" endpoint that takes a
//    4-element input vector [a, b, c, d] and returns an "efficiency score".
// 2. A "model dump" endpoint exposes the weights and biases of the network.
// 3. Layer 1: weights W1 (4x4 matrix) + bias b1 (4-vector) → ReLU
//    Layer 2: weights W2 (4x1 vector) + bias b2 (scalar) → output
// 4. The challenge: find an input vector where the output is EXACTLY
//    the "magic number" (derived from seed). If it matches, the API returns
//    the proof.
// 5. To solve: reverse the network math. Since ReLU(x) = max(0,x), players
//    need to figure out which neurons are active and solve the linear system.
// 6. Additional twist: the weights are floating point, requiring careful math.

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

// Derive deterministic model from seed
function deriveModel(seed) {
    // Layer 1: 4x4 weight matrix (small integer weights for solvability)
    const W1 = [];
    for (let i = 0; i < 4; i++) {
        const row = [];
        for (let j = 0; j < 4; j++) {
            // Weights between -5 and 5
            const raw = simpleHash(seed, `w1:${i}:${j}`);
            row.push(((raw % 11) - 5));
        }
        W1.push(row);
    }

    // Layer 1 biases
    const b1 = [];
    for (let i = 0; i < 4; i++) {
        b1.push((simpleHash(seed, `b1:${i}`) % 7) - 3);
    }

    // Layer 2: 4-element weight vector
    const W2 = [];
    for (let i = 0; i < 4; i++) {
        W2.push(((simpleHash(seed, `w2:${i}`) % 9) - 4));
    }

    // Layer 2 bias
    const b2 = (simpleHash(seed, 'b2') % 11) - 5;

    // Target output: derived from seed
    // We compute forward pass with a known input to get a feasible target
    const knownInput = [];
    for (let i = 0; i < 4; i++) {
        knownInput.push((simpleHash(seed, `ki:${i}`) % 19) - 9);
    }

    // Forward pass with known input to get target
    const hidden = [];
    for (let i = 0; i < 4; i++) {
        let sum = b1[i];
        for (let j = 0; j < 4; j++) {
            sum += W1[i][j] * knownInput[j];
        }
        hidden.push(Math.max(0, sum)); // ReLU
    }

    let target = b2;
    for (let i = 0; i < 4; i++) {
        target += W2[i] * hidden[i];
    }

    return { W1, b1, W2, b2, target: Math.round(target), knownInput };
}

function forwardPass(input, model) {
    const { W1, b1, W2, b2 } = model;

    // Layer 1: affine + ReLU
    const hidden = [];
    for (let i = 0; i < 4; i++) {
        let sum = b1[i];
        for (let j = 0; j < 4; j++) {
            sum += W1[i][j] * input[j];
        }
        hidden.push(Math.max(0, sum));
    }

    // Layer 2: affine (no activation)
    let output = b2;
    for (let i = 0; i < 4; i++) {
        output += W2[i] * hidden[i];
    }

    return { hidden, output: Math.round(output) };
}

module.exports = async function handler(req, res) {
    try {
        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        const seed = url.searchParams.get('seed') || '';
        const action = url.searchParams.get('action') || 'info';

        if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
            return json(res, 400, { error: 'Missing or invalid seed' });
        }

        const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'ai-optimizer' });
        const model = deriveModel(seed);

        if (action === 'info') {
            return json(res, 200, {
                ok: true,
                system: 'SDG9 AI Infrastructure Optimizer v1.0',
                description: 'Neural network predicts infrastructure efficiency from a 4-dimensional input vector.',
                target_output: model.target,
                note: 'Find an input vector [a, b, c, d] (integers) that produces exactly the target output.',
                endpoints: {
                    model: '?seed=<seed>&action=model — Dump the network weights and biases.',
                    infer: 'POST ?seed=<seed>&action=infer — Run inference. Body: { "input": [a, b, c, d] }',
                },
                hints: [
                    'The network has 2 layers: a 4→4 hidden layer with ReLU, then a 4→1 output layer.',
                    'Dump the weights first, then work backwards from the target output.',
                    'ReLU means max(0, x). Figure out which hidden neurons are active for your input.',
                    'For integer weights, a system of linear equations may have integer solutions.',
                ],
            });
        }

        if (action === 'model') {
            return json(res, 200, {
                ok: true,
                model: {
                    architecture: '4 → 4 (ReLU) → 1 (linear)',
                    layer1: {
                        weights: model.W1,
                        biases: model.b1,
                        activation: 'ReLU (max(0, x))',
                    },
                    layer2: {
                        weights: model.W2,
                        bias: model.b2,
                        activation: 'none (linear)',
                    },
                },
                target_output: model.target,
                note: 'Find integer input [a, b, c, d] where forward_pass(input) == target_output.',
            });
        }

        if (action === 'infer') {
            if (req.method !== 'POST') {
                return json(res, 405, { error: 'Infer action requires POST' });
            }

            const body = await readBody(req);
            const input = body.input;

            if (!Array.isArray(input) || input.length !== 4) {
                return json(res, 400, { error: 'Input must be an array of 4 numbers: [a, b, c, d]' });
            }

            for (let i = 0; i < 4; i++) {
                if (typeof input[i] !== 'number' || !Number.isFinite(input[i])) {
                    return json(res, 400, { error: `input[${i}] must be a finite number` });
                }
                // Bound inputs to prevent abuse
                if (Math.abs(input[i]) > 1000) {
                    return json(res, 400, { error: `input[${i}] out of range (max absolute value 1000)` });
                }
            }

            const { hidden, output } = forwardPass(input, model);

            if (output === model.target) {
                return json(res, 200, {
                    ok: true,
                    input,
                    hidden_layer: hidden,
                    output,
                    target: model.target,
                    match: true,
                    message: 'Target output matched! Optimization token follows.',
                    optimization_token: proof,
                });
            }

            return json(res, 200, {
                ok: true,
                input,
                hidden_layer: hidden,
                output,
                target: model.target,
                match: false,
                difference: output - model.target,
                hint: output > model.target
                    ? 'Output too high. Adjust your input to reduce the score.'
                    : 'Output too low. Adjust your input to increase the score.',
            });
        }

        return json(res, 400, { error: 'Unknown action. Use info, model, or infer.' });
    } catch (e) {
        const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
        return json(res, 500, { error: msg });
    }
};
