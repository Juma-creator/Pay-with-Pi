const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

// Configure axios with security headers
const apiClient = axios.create({
  baseURL: process.env.PI_API_URL || 'https://api.minepi.com',
  timeout: 5000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor for security
apiClient.interceptors.request.use((config) => {
  // Don't log sensitive data
  console.log(`[API] ${config.method.toUpperCase()} ${config.url}`);
  return config;
});

// Add response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('[API Error]', error.response?.status || error.message);
    // Don't expose detailed error messages
    throw new Error('Authentication failed');
  }
);

/**
 * Authenticate user securely
 * @param {string} accessToken - User's access token
 * @returns {Promise<object>} Authentication response
 */
async function authenticateUser(accessToken) {
  try {
    // Validate token format
    if (!accessToken || typeof accessToken !== 'string' || accessToken.length === 0) {
      throw new Error('Invalid access token');
    }

    // Make authenticated request
    const response = await apiClient.post('/auth', {
      accessToken,
    });

    // Verify response signature (if Pi provides one)
    if (response.headers['x-signature']) {
      const isValid = verifySignature(
        JSON.stringify(response.data),
        response.headers['x-signature'],
        process.env.PI_PUBLIC_KEY
      );
      if (!isValid) {
        throw new Error('Invalid response signature');
      }
    }

    // Extract only necessary data, don't log full response
    const { user, token } = response.data;
    console.log(`[Auth] User authenticated successfully`);

    return { user, token };
  } catch (error) {
    console.error('[Auth Error]', error.message);
    throw error;
  }
}

/**
 * Verify Pi Network webhook/response signature
 * @param {string} payload - Response payload
 * @param {string} signature - Response signature
 * @param {string} publicKey - Pi's public key
 * @returns {boolean} Whether signature is valid
 */
function verifySignature(payload, signature, publicKey) {
  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(payload);
    return verifier.verify(publicKey, signature, 'base64');
  } catch (error) {
    console.error('Signature verification failed:', error.message);
    return false;
  }
}

/**
 * Refresh access token securely
 * @param {string} refreshToken - User's refresh token
 * @returns {Promise<object>} New access token
 */
async function refreshAccessToken(refreshToken) {
  try {
    if (!refreshToken) throw new Error('Refresh token required');

    const response = await apiClient.post('/auth/refresh', {
      refreshToken,
    });

    return { accessToken: response.data.accessToken };
  } catch (error) {
    console.error('[Refresh Error]', error.message);
    throw error;
  }
}

/**
 * Validate user Pi wallet
 * @param {string} accessToken - User's access token
 * @returns {Promise<object>} User wallet info
 */
async function getUserWallet(accessToken) {
  try {
    if (!accessToken) throw new Error('Access token required');

    const response = await apiClient.get('/me', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    return {
      userId: response.data.uid,
      username: response.data.username,
      walletAddress: response.data.walletAddress,
    };
  } catch (error) {
    console.error('[Wallet Error]', error.message);
    throw error;
  }
}

module.exports = {
  authenticateUser,
  verifySignature,
  refreshAccessToken,
  getUserWallet,
};
