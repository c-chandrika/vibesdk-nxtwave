/**
 * Password Service using Web Crypto API
 * Provides secure password hashing and validation
 * 
 * IMPORTANT: This service uses Web Crypto API (crypto.subtle) which is supported in Cloudflare Workers.
 * It does NOT use bcrypt or Node.js crypto modules, which are unsupported in Cloudflare Workers.
 * 
 * WARNING: Email/password authentication (register/login) should NEVER be invoked in token authentication mode.
 * Token mode is designed for embedded/API usage where users authenticate via external JWTs.
 * Email/password operations are only supported in cookie authentication mode (localhost or custom domains).
 */

import { PasswordValidationResult } from '../types/auth-types';
import { validatePassword } from './validationUtils';
import { createLogger } from '../logger';
import { pbkdf2, timingSafeEqualBytes } from './cryptoUtils';

const logger = createLogger('PasswordService');

/**
 * Password Service for secure password operations
 * 
 * Implementation Details:
 * - Uses PBKDF2 with Web Crypto API (crypto.subtle.deriveBits)
 * - Uses crypto.getRandomValues for salt generation
 * - Uses crypto.subtle.timingSafeEqual for constant-time comparison
 * - All operations are compatible with Cloudflare Workers runtime
 * 
 * This service does NOT use:
 * - bcrypt (Node.js native module, unsupported in Workers)
 * - Node.js crypto.pbkdf2 (unsupported in Workers)
 * - Any Node.js native modules
 * 
 * @see cryptoUtils.pbkdf2 for the Web Crypto API implementation
 */
export class PasswordService {
    private readonly saltLength = 16;
    private readonly iterations = 100000; // OWASP recommended minimum
    private readonly keyLength = 32; // 256 bits
    
    /**
     * Hash a password
     */
    async hash(password: string): Promise<string> {
        try {
            // Generate salt
            const salt = crypto.getRandomValues(new Uint8Array(this.saltLength));
            
            // Hash password
            const hash = await pbkdf2(password, salt, this.iterations, this.keyLength);
            
            // Combine salt and hash for storage
            const combined = new Uint8Array(salt.length + hash.length);
            combined.set(salt);
            combined.set(hash, salt.length);
            
            // Encode as base64 using a method that works in Cloudflare Workers
            // Convert Uint8Array to base64 without using spread operator (which can fail with large arrays)
            const base64 = this.uint8ArrayToBase64(combined);
            return base64;
        } catch (error) {
            logger.error('Error hashing password', { error, errorMessage: error instanceof Error ? error.message : String(error) });
            throw new Error('Failed to hash password');
        }
    }
    
    /**
     * Convert Uint8Array to base64 string (Cloudflare Workers compatible)
     */
    private uint8ArrayToBase64(bytes: Uint8Array): string {
        // Use TextDecoder/TextEncoder approach or manual base64 encoding
        // Cloudflare Workers supports btoa but not with spread operator for large arrays
        let binary = '';
        const len = bytes.length;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    /**
     * Verify a password against a hash
     */
    async verify(password: string, hashedPassword: string): Promise<boolean> {
        try {
            // Decode from base64
            const binary = atob(hashedPassword);
            const combined = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                combined[i] = binary.charCodeAt(i);
            }
            
            // Extract salt and hash
            const salt = combined.slice(0, this.saltLength);
            const originalHash = combined.slice(this.saltLength);
            
            // Hash the provided password with the same salt
            const newHash = await pbkdf2(password, salt, this.iterations, this.keyLength);
            
            // Compare hashes
            return timingSafeEqualBytes(originalHash, newHash);
        } catch (error) {
            logger.error('Error verifying password', { error, errorMessage: error instanceof Error ? error.message : String(error) });
            return false;
        }
    }
    
    /**
     * Validate password strength using centralized validation
     */
    validatePassword(password: string, userInfo?: { email?: string; name?: string }): PasswordValidationResult {
        return validatePassword(password, undefined, userInfo);
    }
}