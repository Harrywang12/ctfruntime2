// Vercel Serverless Function
// Intended "direct object" route (always restricted in this challenge).

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

module.exports = async function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const id = url.searchParams.get('id') || '';
  return json(res, 403, {
    error: 'Case details are restricted on this route.',
    hint: 'The dashboard uses an aggregated endpoint; investigate its filters.',
    caseId: id || null,
  });
};
