import type { Request, Response } from 'express';
import express from 'express';
import { initializeApp, getApps } from 'firebase/app';
import {
  getFirestore,
  collection,
  getDocs,
  doc,
  setDoc,
  deleteDoc,
  query,
  where,
} from 'firebase/firestore';
import crypto from 'crypto';
import firebaseConfig from '../firebase-applet-config.json' with { type: 'json' };

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, x-admin-email');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

const firebaseApp = getApps().length === 0 ? initializeApp(firebaseConfig) : getApps()[0];
const db = getFirestore(firebaseApp, firebaseConfig.firestoreDatabaseId);

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password: string, combinedHash?: string): boolean {
  if (!combinedHash) return false;
  if (!combinedHash.includes(':')) {
    return password === combinedHash;
  }
  const [salt, originalHash] = combinedHash.split(':');
  if (!salt || !originalHash) return false;
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === originalHash;
}

function verifyAdminAuthorization(req: Request): boolean {
  const adminHeader = (req.headers['x-admin-email'] as string || '').toLowerCase().trim();
  const adminBody = (req.body?.adminEmail as string || '').toLowerCase().trim();
  const adminQuery = (req.query?.adminEmail as string || '').toLowerCase().trim();
  const authHeader = (req.headers.authorization || '').toLowerCase().trim();

  return (
    adminHeader === 'admin@blaze.com.pk' ||
    adminBody === 'admin@blaze.com.pk' ||
    adminQuery === 'admin@blaze.com.pk' ||
    authHeader.includes('admin@blaze.com.pk') ||
    authHeader.includes('jwt_admin_session_pk_blaze_9831')
  );
}

// Status
app.get(['/api/status', '/status'], (_req: Request, res: Response) => {
  res.json({
    status: 'ONLINE',
    service: 'Blaze OOH Media Asset Management API (Vercel Serverless)',
    version: '4.2.0-vercel',
    timestamp: new Date().toISOString(),
  });
});

// Login
app.post(['/api/auth/login', '/auth/login'], async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const cleanEmail = (email || '').toLowerCase().trim();

  if (!cleanEmail || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  if (cleanEmail === 'admin@blaze.com.pk') {
    if (password !== 'blaze@admin2026') {
      return res.status(401).json({ error: 'Invalid password for official administrator account.' });
    }
    return res.json({
      success: true,
      user: {
        id: 'usr_admin_01',
        email: 'admin@blaze.com.pk',
        name: 'Admin',
        role: 'administrator',
        organization: 'Blaze Media (Pvt) Ltd - Operations HQ',
        designation: 'Chief Commercial & Operations Officer',
        permissions: {
          canAddAsset: true,
          canEditAsset: true,
          canDeleteAsset: true,
          canImportExcel: true,
          canEditRates: true,
          canManageVendors: true,
          canExportProposal: true,
          canRequestBooking: true,
        },
      },
      message: 'Logged in successfully with full Administrator privileges.',
    });
  }

  try {
    const q = query(collection(db, 'users'), where('email', '==', cleanEmail));
    const snap = await getDocs(q);

    if (snap.empty) {
      return res.status(401).json({
        error: 'No client account found for this email address. Please check your credentials or contact Blaze Media operations.',
      });
    }

    let clientDoc: any = null;
    snap.forEach((d) => {
      const data = d.data();
      if (data.passwordHash && !clientDoc) {
        clientDoc = { ...data, id: d.id };
      }
    });

    if (!clientDoc || !clientDoc.passwordHash) {
      return res.status(401).json({
        error: 'Account credentials have not been configured yet. Please ask the administrator to issue or reset your password.',
      });
    }

    if (!verifyPassword(password, clientDoc.passwordHash)) {
      return res.status(401).json({
        error: 'Invalid password. Please enter the password issued by your administrator.',
      });
    }

    const { passwordHash: _, ...safeUser } = clientDoc;
    return res.json({
      success: true,
      user: {
        ...safeUser,
        role: 'client',
        permissions: {
          canAddAsset: false,
          canEditAsset: false,
          canDeleteAsset: false,
          canImportExcel: false,
          canEditRates: false,
          canManageVendors: false,
          canExportProposal: true,
          canRequestBooking: true,
        },
      },
      message: `Logged in successfully as ${clientDoc.name}.`,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// Admin Get Clients
app.get(['/api/admin/clients', '/admin/clients', '/api/clients', '/clients'], async (req: Request, res: Response) => {
  if (!verifyAdminAuthorization(req)) {
    return res.status(403).json({ error: 'Access denied: Administrator privileges required.' });
  }

  try {
    const snap = await getDocs(collection(db, 'users'));
    const clients: any[] = [];
    snap.forEach((d) => {
      const data = d.data();
      if (data.role === 'client' || !data.role) {
        const { passwordHash: _, ...safe } = data;
        clients.push({ ...safe, id: d.id, permittedCities: [] });
      }
    });
    clients.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    res.json({ clients });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Admin Create Client
app.post(['/api/admin/clients', '/admin/clients', '/api/clients', '/clients'], async (req: Request, res: Response) => {
  if (!verifyAdminAuthorization(req)) {
    return res.status(403).json({ error: 'Access denied: Administrator privileges required.' });
  }

  const { id, name, email, organization, designation, temporaryPassword, initialPassword } = req.body;
  if (!email || !name) {
    return res.status(400).json({ error: 'Name and email are required to issue client credentials.' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const rawPassword = initialPassword || temporaryPassword || '';
  const passwordHash = rawPassword ? hashPassword(rawPassword) : undefined;
  const clientId = id || `usr_client_${Date.now().toString().slice(-6)}`;

  const clientRecord = {
    id: clientId,
    name: name.trim(),
    email: cleanEmail,
    organization: organization?.trim() || 'Advertiser Agency Client',
    designation: designation?.trim() || 'Media Planning Executive',
    role: 'client' as const,
    status: 'Active',
    permittedCities: [],
    createdAt: new Date().toISOString(),
    createdBy: 'admin@blaze.com.pk',
    ...(passwordHash ? { passwordHash } : {}),
  };

  try {
    await setDoc(doc(db, 'users', clientId), clientRecord, { merge: true });
    const { passwordHash: _, ...safeClient } = clientRecord;
    res.status(201).json({
      success: true,
      client: safeClient,
      message: `Client account provisioned for ${clientRecord.name} (${clientRecord.email}).`,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Admin Reset Password
app.post([
  '/api/admin/clients/:id/reset-password',
  '/admin/clients/:id/reset-password',
  '/api/admin/clients/reset-password',
  '/admin/clients/reset-password',
], async (req: Request, res: Response) => {
  if (!verifyAdminAuthorization(req)) {
    return res.status(403).json({ error: 'Access denied: Administrator privileges required.' });
  }

  const rawId = req.params.id ? decodeURIComponent(req.params.id) : (req.body.clientId || req.body.id || '');
  const clientId = String(rawId || '').trim();
  const { newPassword, email } = req.body;

  if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters long.' });
  }

  const cleanEmail = (email || '').toLowerCase().trim();
  const secureHash = hashPassword(newPassword);

  try {
    if (clientId) {
      await setDoc(doc(db, 'users', clientId), { passwordHash: secureHash, updatedAt: new Date().toISOString() }, { merge: true });
    }
    if (cleanEmail) {
      const q = query(collection(db, 'users'), where('email', '==', cleanEmail));
      const snap = await getDocs(q);
      for (const d of snap.docs) {
        await setDoc(d.ref, { passwordHash: secureHash, updatedAt: new Date().toISOString() }, { merge: true });
      }
    }

    res.json({
      success: true,
      message: `Password has been reset securely for ${cleanEmail || clientId}.`,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default app;
