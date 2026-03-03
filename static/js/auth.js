// Light encryption helper with AES-GCM

// 1. Password (Last+Zip) -> Derives Decryption Key via PBKDF2
// 2. Hash(Last+Zip) -> Filename (Key Hash).
// 3. User fetches Filename.json, then decrypts it with Key.

// Helpers
async function hashString(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

// Helper to get key (Cached or Derived)
async function getDecryptionKey(password, salt) {
    // construct base64 salt identifier to validate cache
    const saltB64 = btoa(String.fromCharCode(...salt));
    
    // 1. Try to load cached key from session IF salt matches
    const cachedJwk = sessionStorage.getItem('wedding_auth_key_jwk');
    const cachedSalt = sessionStorage.getItem('wedding_auth_key_salt');

    if (cachedJwk && cachedSalt === saltB64) {
        try {
            return await crypto.subtle.importKey(
                "jwk",
                JSON.parse(cachedJwk),
                { name: "AES-GCM" },
                false,
                ["decrypt"]
            );
        } catch (e) {
            console.warn("Invalid cached key, re-deriving...");
            sessionStorage.removeItem('wedding_auth_key_jwk');
            sessionStorage.removeItem('wedding_auth_key_salt');
        }
    }

    // 2. Derive Key (Slow)
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw", 
        enc.encode(password), 
        { name: "PBKDF2" }, 
        false, 
        ["deriveKey"]
    );
    
    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true, // Extractable for caching
        ["decrypt"]
    );

    // 3. Cache it
    try {
        const jwk = await crypto.subtle.exportKey("jwk", key);
        sessionStorage.setItem('wedding_auth_key_jwk', JSON.stringify(jwk));
        sessionStorage.setItem('wedding_auth_key_salt', saltB64);
    } catch(e) {
        console.warn("Failed to cache key", e);
    }
    
    return key;
}

// AES Decryption
async function decrypt(encryptedWrapper, password) {
    if (!encryptedWrapper.salt || !encryptedWrapper.iv || !encryptedWrapper.data) {
        throw new Error("Invalid encrypted data format");
    }

    try {
        // 1. Decode Base64 components
        const salt = Uint8Array.from(atob(encryptedWrapper.salt), c => c.charCodeAt(0));
        const iv = Uint8Array.from(atob(encryptedWrapper.iv), c => c.charCodeAt(0));
        const data = Uint8Array.from(atob(encryptedWrapper.data), c => c.charCodeAt(0));

        // 2. Get Key (Cached or Derived)
        const key = await getDecryptionKey(password, salt);

        // 3. Decrypt
        const decryptedBuffer = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            data
        );
        
        const dec = new TextDecoder();
        return JSON.parse(dec.decode(decryptedBuffer));
    } catch (e) {
        console.error("Decryption failed", e);
        sessionStorage.removeItem('wedding_auth_key_jwk');
        throw new Error("Invalid Password or Corrupted Data");
    }
}

async function loginUser(lastName, zipCode) {
    // Clear any stale session keys to force re-derivation with new salt/password
    sessionStorage.removeItem('wedding_auth_key_jwk');
    sessionStorage.removeItem('wedding_auth_file_id');
    sessionStorage.removeItem('wedding_auth_password');

    if(!lastName || !zipCode) {
        alert("Please enter both Last Name and Zip Code.");
        const l = document.getElementById('loading-message');
        if(l) l.innerText = "";
        return;
    }

    const normLast = lastName.toLowerCase().replace(/\s/g, '').replace(/'/g, '');
    const normZip = zipCode.replace(/\s/g, '').replace(/-/g, ''); 
    
    // This is the password for encryption key derivation
    const password = `${normLast}${normZip}`; 
    
    // Hash for Lookup
    const key = `${normLast}_${normZip}`;

    try {
        const hash = await hashString(key);
        
        // Lookup file ID
        // Use relative path for compatibility with subdirectories on GitHub Pages
        // Add cache buster
        const response = await fetch(`data/lookup.json?cb=${Date.now()}`);
        if (!response.ok) throw new Error("Could not load lookup table");
        
        const lookup = await response.json();
        const fileId = lookup[hash]; // This is the encrypted file's name (without extension)

        if (fileId) {
            // Fetch Encrypted File
            const fileResp = await fetch(`data/invites/${fileId}.json?cb=${Date.now()}`);
            if(!fileResp.ok) throw new Error("File not found");
            const encryptedData = await fileResp.json();
            
            // Decrypt it
            await decrypt(encryptedData, password);
            console.log("Decrypted successfully!");
            
            // Store credentials in Session Storage (cleared on browser close)
            sessionStorage.setItem('wedding_auth_password', password);
            sessionStorage.setItem('wedding_auth_file_id', fileId);
            
            // Clear local storage legacy from unencrypted version
            localStorage.removeItem('wedding_invite_id');
            
            window.location.reload();
        } else {
            const l = document.getElementById('loading-message');
            if(l) l.innerText = "";
            alert("Invitation not found. Please check spelling or zip code.");
        }

    } catch (e) {
        console.error(e);
        const l = document.getElementById('loading-message');
        if(l) l.innerText = "";
        alert("Login failed. Check your name and zip code.");
    }
}

function logoutUser() {
    sessionStorage.removeItem('wedding_auth_password');
    sessionStorage.removeItem('wedding_auth_file_id');
    sessionStorage.removeItem('wedding_auth_key_jwk');
    sessionStorage.removeItem('wedding_auth_key_salt');
    window.location.href = '/index.html';
}

async function getInviteData() {
    const fileId = sessionStorage.getItem('wedding_auth_file_id');
    const password = sessionStorage.getItem('wedding_auth_password');
    
    console.log("getInviteData: Checking credentials...");
    if (!fileId || !password) {
        console.warn("getInviteData: Missing credentials in sessionStorage");
        return null; // Not logged in
    }
    
    try {
        // Fetch Encrypted
        const url = `data/invites/${fileId}.json?cb=${Date.now()}`;
        console.log("getInviteData: Fetching", url);
        
        const response = await fetch(url);
        if (response.ok) {
            console.log("getInviteData: Fetch success. Parsing JSON...");
            const encryptedData = await response.json();
            console.log("getInviteData: Decrypting...");
            const data = await decrypt(encryptedData, password);
            console.log("getInviteData: Decryption complete.", data ? "Success" : "Failed");
            return data;
        } else {
            console.error("getInviteData: Fetch failed", response.status, response.statusText);
            // Invalid file
            logoutUser();
        }
    } catch(e) {
        console.error("Failed to load invite data", e);
    }
    return null;
}

// Global state
let currentInvite = null;

document.addEventListener('DOMContentLoaded', async () => {
    
    // Inject CSS if missing
    if(!document.querySelector('link[href*="auth.css"]')){
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = '/static/css/auth.css';
        document.head.appendChild(link);
    }

    const body = document.body;
    
    // Optimistic UI: If we have credentials, show logged-in state immediately
    if (sessionStorage.getItem('wedding_auth_file_id') && sessionStorage.getItem('wedding_auth_password')) {
        body.classList.add('logged-in');
        body.classList.remove('logged-out');
    } else {
        body.classList.add('logged-out');
        body.classList.remove('logged-in');
    }

    // Check Login State (Validate & Decrypt)
    try {
        currentInvite = await getInviteData();
        
        if (currentInvite) {
            // Confirm logged-in state
            body.classList.add('logged-in');
            body.classList.remove('logged-out');
            
            // Personalization
            if (currentInvite.people) {
                const names = currentInvite.people.map(p => p.first_name).join(' & ');
                document.querySelectorAll('.guest-names').forEach(el => el.innerText = names);
            }
        } else {
            // Only if credentials existed but failed
            if (sessionStorage.getItem('wedding_auth_file_id')) {
                console.warn("Stored credentials invalid or expired.");
                logoutUser(); 
            }
            body.classList.add('logged-out');
            body.classList.remove('logged-in');
        }
    } catch (e) {
        console.error("Auth check failed", e);
        body.classList.add('logged-out');
        body.classList.remove('logged-in');
    }

    // Attach Event Listeners
    const findBtn = document.getElementById('find-button');
    if (findBtn) {
        findBtn.addEventListener('click', () => {
            const last = document.getElementById('last_name').value;
            const zip = document.getElementById('zip_code').value;
            const l = document.getElementById('loading-message');
            if(l) l.innerText = "Finding...";
            
            // Use setTimeout to allow UI to update 
            setTimeout(() => {
                loginUser(last, zip);
            }, 10);
        });
    }
    
    const zipInput = document.getElementById('zip_code');
    const lastInput = document.getElementById('last_name');
    
    function handleEnter(e) {
        if (e.key === 'Enter') {
            findBtn.click();
        }
    }
    
    if(zipInput) zipInput.addEventListener('keypress', handleEnter);
    if(lastInput) lastInput.addEventListener('keypress', handleEnter);
});
