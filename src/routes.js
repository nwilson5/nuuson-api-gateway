// Route table for api.nuuson.dev
// Format: '/v1/<service>/': 'https://<backend-url>'
//
// Updated automatically via PR when a new service is deployed.
// Backend URLs should be internal subdomains protected by Cloudflare Access.

export const ROUTES = {
  '/v1/testing/': 'https://testing-internal.nuuson.dev',
};
