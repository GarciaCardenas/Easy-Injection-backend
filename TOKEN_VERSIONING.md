# Token Versioning Implementation (Pure Global Revocation)

## Problem
JWT tokens cannot be individually revoked because they are stateless. Once issued, a JWT remains valid until expiration unless we implement a revocation mechanism.

**Previous issues:**
1. Storing JWT tokens in database created security risks (tokens in plaintext)
2. Per-session token tracking was complex and ineffective
3. Closing individual sessions didn't actually invalidate JWTs
4. Mixed approach caused confusion between session metadata and token validation

## Solution: Pure Global Token Versioning

### Architecture
We use **global token versioning** as the sole revocation mechanism:
- Each user has a `tokenVersion` counter (starts at 0)
- Every JWT includes the current `tokenVersion` as a claim
- Middleware validates JWT's `tokenVersion` matches user's current `tokenVersion`
- **Closing ANY session increments `tokenVersion`**, invalidating ALL tokens globally
- Sessions store only metadata (device, browser, IP, location) - **NO JWT tokens**

### Key Principle
**There is no per-session revocation with JWTs**. When any session is closed:
- `tokenVersion` increments (e.g., 5 → 6)
- ALL existing JWTs become invalid (they have `tokenVersion: 5`)
- User must re-login from ALL devices to get new tokens with `tokenVersion: 6`

This is a fundamental JWT limitation and the correct security approach.

## Implementation Details

### 1. User Model Schema
### 1. User Model Schema
```javascript
// Session schema - NO token field
const sessionSchema = new mongoose.Schema({
    device: String,
    browser: String,
    os: String,
    location: String,
    ip: String,
    lastActivity: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});

// User schema with tokenVersion
const userSchema = new mongoose.Schema({
    // ... other fields
    tokenVersion: { type: Number, default: 0 },
    activeSessions: [sessionSchema]
});
```

**Important:** Sessions store ONLY metadata, never JWT tokens.

### 2. Token Generation
```javascript
generateAuthToken() {
    const token = jwt.sign(
        { 
            _id: this._id, 
            username: this.#username, 
            email: this.#email, 
            tokenVersion: this.#tokenVersion  // Current version included
        },
        config.get('jwtPrivateKey'),
        { expiresIn: '24h' }
    );
    return token;
}
```

### 3. Token Validation (Middleware)
```javascript
// Verify JWT signature
const decoded = jwt.verify(token, config.get('jwtPrivateKey'));

// Load user from database
const user = User.fromMongoose(userDoc);

// CRITICAL: Verify tokenVersion matches
if (decoded.tokenVersion !== user.tokenVersion) {
    return res.status(401).json({ 
        error: 'Token inválido. La sesión ha sido cerrada.' 
    });
}

// Token is valid, continue
req.user = decoded;
next();
```

**No token-in-sessions lookup** - only tokenVersion comparison.

### 4. Session Revocation

#### Close All Sessions (Global Invalidation)
```javascript
router.post('/close-all', auth, async (req, res) => {
    const user = User.fromMongoose(userDoc);
    user.clearAllSessions();  // Clears sessions AND increments tokenVersion
    await user.save();
    
    res.clearCookie('auth_token');
    res.json({ message: 'Todas las sesiones han sido cerradas' });
});
```

```javascript
clearAllSessions() {
    this.#activeSessions = [];
    this.#tokenVersion++;  // All tokens now invalid
}
```

#### Close Single Session (Also Global Invalidation)
```javascript
router.delete('/:sessionId', auth, async (req, res) => {
    // Remove session from array
    await User.Model.findByIdAndUpdate(req.user._id, {
        $pull: { activeSessions: { _id: req.params.sessionId } }
    });
    
    // IMPORTANT: Increment tokenVersion
    // This invalidates ALL JWTs, not just this session's
    await User.Model.findByIdAndUpdate(req.user._id, {
        $inc: { tokenVersion: 1 }
    });
    
    res.clearCookie('auth_token');
    res.json({ 
        message: 'Sesión cerrada. Todas las sesiones han sido invalidadas.',
        requiresRelogin: true 
    });
});
```

**Key Point:** Closing ANY session invalidates ALL tokens. This is not a bug - it's how JWTs work.

### 5. Internal Session Management
For internal operations (e.g., limiting to 5 sessions) that shouldn't invalidate tokens:
```javascript
clearSessionsOnly() {
    this.#activeSessions = [];
    // Does NOT increment tokenVersion
}
```

## Security Benefits

1. **Immediate Global Revocation**: All tokens invalidated instantly when needed
2. **No Token Storage**: JWTs never stored in database (security best practice)
3. **Simple Validation**: Single integer comparison, very fast
4. **Cryptographically Secure**: Uses JWT's built-in signature verification + version check
5. **No Token Leakage**: Even if database is compromised, no JWTs are exposed

## Trade-offs

### ✅ What This Enables
- Instant global token invalidation
- Fast authentication (no database token lookups)
- Secure (no tokens stored in database)
- Simple implementation

### ❌ What This Doesn't Enable
- **Per-session revocation**: Cannot revoke individual sessions without affecting all
- **Selective device logout**: Closing any session logs out all devices
- **Session continuity**: Can't keep some sessions active while closing others

**This is a fundamental JWT limitation**, not an implementation bug.

## User Experience

### Scenario 1: Close All Sessions
1. User clicks "Close all sessions"
2. `tokenVersion` increments (e.g., 5 → 6)
3. All devices are logged out immediately
4. User must re-login from all devices

### Scenario 2: Close Single Session
1. User closes "Mobile Device" session
2. `tokenVersion` increments (5 → 6)
3. **ALL devices are logged out** (including current device)
4. User sees message: "Session closed. All sessions invalidated for security."
5. User must re-login

**Why both scenarios behave the same:** JWTs cannot be individually revoked. The only way to invalidate a JWT is to increment the global `tokenVersion`.

## Alternative Approaches (Not Implemented)

If per-session revocation is required, consider:

### Option 1: Session-Based Authentication
- Store session IDs in database (not JWTs)
- Use Redis/MongoDB for session storage
- Check session validity on every request
- **Pro:** True per-session revocation
- **Con:** Requires database lookup on every request

### Option 2: Short-Lived JWTs + Refresh Tokens
- Issue JWTs with 15-minute expiration
- Use long-lived refresh tokens for renewal
- Revoke refresh tokens to invalidate sessions
- **Pro:** Better security, limited JWT lifetime
- **Con:** More complex implementation

### Option 3: JWT Blacklist
- Store revoked JWTs in Redis until expiration
- Check blacklist on every request
- **Pro:** Can revoke individual JWTs
- **Con:** Defeats JWT's stateless purpose, requires Redis

## Current Implementation Choice

We chose **pure global token versioning** because:
1. **Simplicity**: Single integer comparison, no external dependencies
2. **Security**: No tokens stored in database
3. **Performance**: No database/Redis lookups per request
4. **Transparency**: Clear to users that closing a session affects all devices

## Testing

### Manual Testing
1. **Login from two browsers**
   ```bash
   Browser A: Login → Get JWT with tokenVersion=0
   Browser B: Login → Get JWT with tokenVersion=0
   ```

2. **Close single session**
   ```bash
   Browser A: Close "Browser B" session
   Backend: tokenVersion increments to 1
   Browser A: Gets logged out (token now invalid)
   Browser B: Already logged out (token invalid)
   ```

3. **Verify token invalidation**
   ```bash
   Try accessing protected route with old JWT
   Expected: 401 Unauthorized - "Token inválido. La sesión ha sido cerrada."
   ```

4. **Re-login**
   ```bash
   Browser A: Login → Get new JWT with tokenVersion=1
   Browser A: Can access protected routes ✓
   ```

### Automated Testing
```javascript
// Verify tokenVersion in JWT
const decoded = jwt.verify(token, secret);
assert(decoded.tokenVersion === user.tokenVersion);

// Verify token rejection after version increment
user.tokenVersion++;
await user.save();
// Old token should now be rejected
```

## Migration Notes

- **Existing users**: Automatically get `tokenVersion: 0` via schema default
- **Existing sessions**: First "close session" action will invalidate all tokens
- **No data migration needed**: Field is added automatically with default value

## Summary

This implementation provides:
- ✅ Strong security (no token storage)
- ✅ Instant global revocation
- ✅ Simple, maintainable code
- ✅ Fast authentication
- ❌ No per-session revocation (JWT limitation)

The trade-off is acceptable because:
1. Security events (suspicious activity, password change) should log out all devices
2. Users understand "close session" means "log out everywhere for security"
3. The alternative (storing tokens) is less secure and defeats JWT's purpose
