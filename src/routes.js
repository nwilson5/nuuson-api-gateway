// Route table for api.nuuson.dev
// To add a service: one entry here, open a PR.
// Format: '/v1/<service>/': { backend: 'https://<service>-internal.nuuson.dev', scope: '<service>' }

export const ROUTES = {
  '/v1/testing/': {
    backend: 'https://testing-internal.nuuson.dev',
    scope: 'testing',
  },
};
