/**
 * API Configuration - Centralized URL management
 *
 * This module ensures all API calls go directly to the backend server,
 * avoiding issues with Cloudflare Pages proxy not handling CORS preflight.
 */

// Version identifier for debugging cache issues
const API_CONFIG_VERSION = '2026-01-27-v3';


/**
 * Get the API base URL based on environment
 */
export function getApiBaseUrl(): string {
  if (typeof window === 'undefined') return '';

  const hostname = window.location.hostname;

  // Local development - use the same origin so requests hit the webpack devServer's
  // /api proxy (→ local server.js on :8080 → SSH tunnel → prod DB). Same-origin, no CORS.
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return window.location.origin;
  }

  // Staging - use staging.inchambers.ai directly
  if (hostname === 'staging.inchambers.ai') {
    return 'https://staging.inchambers.ai';
  }

  // Production - always use app.inchambers.ai directly
  // This bypasses Cloudflare Pages proxy which doesn't handle CORS preflight
  return 'https://app.inchambers.ai';
}

/**
 * Helper to construct full API URLs
 * @param path - API path (e.g., '/api/admin/users')
 * @returns Full URL (e.g., 'https://app.inchambers.ai/api/admin/users')
 */
export function apiUrl(path: string): string {
  const baseUrl = getApiBaseUrl();
  const fullUrl = `${baseUrl}${path}`;

  // Runtime diagnostic: warn if baseUrl is empty in production browser context
  if (typeof window !== 'undefined' && baseUrl === '' &&
      window.location.hostname !== 'localhost' &&
      window.location.hostname !== '127.0.0.1') {
    console.error('IC-AP003', window.location.hostname, path, fullUrl);
  }

  return fullUrl;
}
