'use strict';

/** LabAccess MVP: API REST + serveur de fichiers sans dépendance externe. */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const FRONTEND = path.join(ROOT, 'frontend');
const DATA_FILE = path.join(__dirname, 'data', 'labaccess.json');
const PORT = Number(process.env.PORT || 3000);
const sessions = new Map();
const ROLE_PERMISSIONS = {
  admin: ['dashboard:read', 'people:read', 'people:manage', 'cards:read', 'cards:manage', 'rooms:read', 'computers:read', 'computers:manage', 'scans:create', 'sessions:read', 'logs:read', 'reservations:read', 'reservations:manage'],
  agent: ['dashboard:read', 'people:read', 'cards:read', 'rooms:read', 'computers:read', 'scans:create', 'sessions:read', 'logs:read', 'reservations:read', 'reservations:manage']
};

function now() { return new Date().toISOString(); }
function id() { return crypto.randomUUID(); }
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
  return `scrypt$${salt}$${derivedKey}`;
}
function verifyPassword(password, storedHash) {
  if (typeof storedHash !== 'string' || !storedHash.startsWith('scrypt$')) return false;
  const [, salt, expectedHex] = storedHash.split('$');
  if (!salt || !expectedHex || !/^[a-f\d]+$/i.test(expectedHex)) return false;
  const actual = crypto.scryptSync(password, salt, expectedHex.length / 2, { N: 16384, r: 8, p: 1 });
  const expected = Buffer.from(expectedHex, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
function seed() {
  return {
    users: [
      { id: 'u-admin', email: 'admin@labaccess.local', password_hash: hashPassword('admin123'), role: 'admin', name: 'Administrateur', is_active: true },
      { id: 'u-agent', email: 'agent@labaccess.local', password_hash: hashPassword('agent123'), role: 'agent', name: 'Agent de sécurité', is_active: true }
    ],
    people: [
      { id: 'p-001', type: 'student', matricule: '2026-0001', firstName: 'Amina', lastName: 'Mukendi', email: 'amina.mukendi@univ.local', faculty: 'Informatique', promotion: 'L2', active: true },
      { id: 'p-002', type: 'student', matricule: '2026-0002', firstName: 'David', lastName: 'Kabasele', email: 'david.kabasele@univ.local', faculty: 'Informatique', promotion: 'L1', active: true },
      { id: 'p-003', type: 'professor', matricule: 'PRF-014', firstName: 'Claire', lastName: 'Ilunga', email: 'claire.ilunga@univ.local', department: 'Informatique', active: true }
    ],
    cards: [
      { id: 'c-001', personId: 'p-001', qr: 'LAB-STU-2026-00001', status: 'active', issuedAt: '2026-01-10' },
      { id: 'c-002', personId: 'p-002', qr: 'LAB-STU-2026-00002', status: 'active', issuedAt: '2026-01-10' },
      { id: 'c-003', personId: 'p-003', qr: 'LAB-PRF-2026-00003', status: 'active', issuedAt: '2026-01-10' }
    ],
    rooms: [
      { id: 'r-lab', name: 'Laboratoire IA', code: 'LAB-IA', type: 'laboratory', capacity: 30, location: 'Bâtiment A — niveau 2' },
      { id: 'r-aud', name: 'Auditoire numérique', code: 'AUD-01', type: 'auditorium', capacity: 80, location: 'Bâtiment B — niveau 1' }
    ],
    computers: [
      { id: 'pc-01', roomId: 'r-lab', code: 'IA-01', name: 'Poste IA 01', status: 'available' },
      { id: 'pc-02', roomId: 'r-lab', code: 'IA-02', name: 'Poste IA 02', status: 'available' },
      { id: 'pc-03', roomId: 'r-lab', code: 'IA-03', name: 'Poste IA 03', status: 'maintenance' },
      { id: 'pc-04', roomId: 'r-lab', code: 'IA-04', name: 'Poste IA 04', status: 'available' }
    ],
    accessSessions: [], reservations: [], logs: []
  };
}
function load() {
  try {
    const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    let changed = false;
    for (const user of data.users || []) {
      if (user.password && !user.password_hash) { user.password_hash = hashPassword(user.password); delete user.password; changed = true; }
      if (user.is_active === undefined) { user.is_active = true; changed = true; }
    }
    if (changed) save(data);
    return data;
  }
  catch { const data = seed(); save(data); return data; }
}
function save(data) { fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true }); fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2)); }
let db = load();
function sanitizeUser(user) { return { id: user.id, email: user.email, role: user.role, name: user.name, permissions: ROLE_PERMISSIONS[user.role] || [] }; }
function personName(person) { return `${person.firstName} ${person.lastName}`; }
function personSummary(person) { return person ? { id: person.id, type: person.type, matricule: person.matricule, firstName: person.firstName, lastName: person.lastName, name: personName(person) } : null; }
function toMinutes(time) {
  if (!time || !/^\d{2}:\d{2}$/.test(time)) return null;
  const [hours, minutes] = time.split(':').map(Number);
  if (Number.isNaN(hours) || Number.isNaN(minutes) || hours < 0 || hours > 23 || minutes < 0 || minutes > 59) return null;
  return hours * 60 + minutes;
}
function findReservationConflict(roomId, date, startTime, endTime, excludeId = null) {
  const startMinutes = toMinutes(startTime);
  const endMinutes = toMinutes(endTime);
  if (startMinutes === null || endMinutes === null || endMinutes <= startMinutes) return null;
  return db.reservations.find(r => {
    if (excludeId && r.id === excludeId) return false;
    if (r.roomId !== roomId || r.date !== date || r.status === 'cancelled') return false;
    const currentStart = toMinutes(r.startTime);
    const currentEnd = toMinutes(r.endTime);
    if (currentStart === null || currentEnd === null || currentEnd <= currentStart) return false;
    return startMinutes < currentEnd && endMinutes > currentStart;
  });
}
function respond(res, status, body) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(body)); }
function error(res, status, message) { respond(res, status, { success: false, message }); }
async function body(req) {
  let raw = ''; for await (const part of req) { raw += part; if (raw.length > 3_000_000) throw new Error('Requête trop volumineuse'); }
  try { return raw ? JSON.parse(raw) : {}; } catch { const e = new Error('JSON invalide'); e.status = 400; throw e; }
}
function auth(req, res, permission) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, ''); const session = sessions.get(token);
  const currentUser = session && db.users.find(candidate => candidate.id === session.user.id);
  const user = session && session.expiresAt > Date.now() && currentUser?.is_active ? sanitizeUser(currentUser) : null;
  if (!user && session) sessions.delete(token);
  if (!user) { error(res, 401, 'Authentification requise'); return null; }
  if (permission && !ROLE_PERMISSIONS[user.role]?.includes(permission)) { error(res, 403, 'Permission insuffisante'); return null; }
  return user;
}
function requirePermission(res, user, permission) {
  if (!ROLE_PERMISSIONS[user.role]?.includes(permission)) { error(res, 403, 'Permission insuffisante'); return false; }
  return true;
}
function listPeople() { return db.people.map(p => ({ ...p, name: personName(p), card: db.cards.find(c => c.personId === p.id) || null })); }
function findPerson(id) { return db.people.find(p => p.id === id); }
function activeSession(personId) { return db.accessSessions.find(s => s.personId === personId && s.status === 'active'); }
function dashboard() {
  const active = db.accessSessions.filter(s => s.status === 'active');
  return { people: db.people.length, activeSessions: active.length, availableComputers: db.computers.filter(c => c.status === 'available').length,
    totalComputers: db.computers.length, reservations: db.reservations.filter(r => r.status !== 'cancelled').length,
    recentSessions: db.accessSessions.slice(-8).reverse().map(enrichSession), active: active.map(enrichSession) };
}
function enrichSession(s) { const p = findPerson(s.personId); const room = db.rooms.find(r => r.id === s.roomId); const pc = db.computers.find(c => c.id === s.computerId); return { ...s, person: p && { ...p, name: personName(p) }, room, computer: pc || null }; }
function validatePerson(input) {
  if (!['student', 'professor'].includes(input.type)) return 'Le type doit être étudiant ou professeur.';
  if (!input.firstName?.trim() || !input.lastName?.trim() || !input.matricule?.trim()) return 'Prénom, nom et matricule sont requis.';
  if (db.people.some(p => p.matricule === input.matricule && p.id !== input.id)) return 'Ce matricule existe déjà.';
  return null;
}
function qrFor(type) { const number = String(db.cards.length + 1).padStart(5, '0'); return `LAB-${type === 'student' ? 'STU' : 'PRF'}-${new Date().getFullYear()}-${number}`; }
function scan(qr, roomId, requestedComputerId, user) {
  if (!/^LAB-(STU|PRF)-\d{4}-\d{5}$/.test(qr)) throw new Error('Format QR invalide. Exemple : LAB-STU-2026-00001.');
  const card = db.cards.find(c => c.qr === qr); if (!card) throw new Error('QR Code inconnu.');
  if (card.status !== 'active') throw new Error(`Accès refusé : carte ${card.status}.`);
  const person = findPerson(card.personId); if (!person?.active) throw new Error('Accès refusé : personne inactive.');
  const ongoing = activeSession(person.id);
  if (ongoing) {
    ongoing.status = 'completed'; ongoing.exitAt = now(); ongoing.durationMinutes = Math.max(0, Math.round((Date.parse(ongoing.exitAt) - Date.parse(ongoing.entryAt)) / 60000));
    if (ongoing.computerId) { const pc = db.computers.find(c => c.id === ongoing.computerId); if (pc && pc.status === 'occupied') pc.status = 'available'; }
 main
    db.logs.push({ id: id(), action: 'exit', personId: person.id, qr, at: now(), agentId: user.id }); save(db);
    return { action: 'exit', message: `Sortie enregistrée pour ${personName(person)}.`, session: enrichSession(ongoing), person: personSummary(person) }
    db.logs.push({ id: id(), sessionId: ongoing.id, action: 'exit', personId: person.id, qr, roomId: ongoing.roomId, computerId: ongoing.computerId, at: ongoing.exitAt, agentId: user.id }); save(db);
    return { action: 'exit', message: `Sortie enregistrée pour ${personName(person)}.`, session: enrichSession(ongoing) }; main
  }
  const room = db.rooms.find(r => r.id === roomId); if (!room) throw new Error('Salle invalide.');
  if (db.accessSessions.filter(s => s.roomId === roomId && s.status === 'active').length >= room.capacity) throw new Error('La capacité de la salle est atteinte.');
  let computerId = null;
  if (requestedComputerId !== 'private' && requestedComputerId) { const pc = db.computers.find(c => c.id === requestedComputerId && c.roomId === roomId); if (!pc || pc.status !== 'available') throw new Error('Ce poste n’est plus disponible.'); pc.status = 'occupied'; computerId = pc.id; }
  const entry = { id: id(), personId: person.id, roomId, computerId, computerType: computerId ? 'lab' : 'private', entryAt: now(), exitAt: null, durationMinutes: null, status: 'active', agentId: user.id };

  main
  db.accessSessions.push(entry); db.logs.push({ id: id(), action: 'entry', personId: person.id, qr, at: now(), agentId: user.id }); save(db);
  return { action: 'entry', message: `Entrée autorisée pour ${personName(person)}.`, session: enrichSession(entry), person: personSummary(person) };
  db.accessSessions.push(entry); db.logs.push({ id: id(), sessionId: entry.id, action: 'entry', personId: person.id, qr, roomId: entry.roomId, computerId: entry.computerId, at: entry.entryAt, agentId: user.id }); save(db);
  return { action: 'entry', message: `Entrée autorisée pour ${personName(person)}.`, session: enrichSession(entry) }; main
}
function staticFile(req, res) {
  const urlPath = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  const relative = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, ''); const file = path.resolve(FRONTEND, relative);
  if (!file.startsWith(FRONTEND) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end('Not found'); }
  const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8' };
  res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream' }); fs.createReadStream(file).pipe(res);
}
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost'); const route = url.pathname; const method = req.method;
    if (!route.startsWith('/api/')) return staticFile(req, res);
    if (method === 'POST' && route === '/api/auth/login') {
      const input = await body(req);
      const email = typeof input.email === 'string' ? input.email.trim().toLowerCase() : '';
      const password = typeof input.password === 'string' ? input.password : '';
      const user = db.users.find(candidate => candidate.email === email);
      if (!user || !user.is_active) return error(res, 401, user ? 'Compte désactivé.' : 'Identifiants invalides.');
      if (!verifyPassword(password, user.password_hash)) return error(res, 401, 'Identifiants invalides.');
      const token = crypto.randomBytes(48).toString('hex');
      const safeUser = sanitizeUser(user);
      sessions.set(token, { user: safeUser, expiresAt: Date.now() + 24 * 60 * 60 * 1000 });
      return respond(res, 200, { success: true, data: { token, user: safeUser } });
    }
    if (method === 'POST' && route === '/api/auth/logout') { const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, ''); sessions.delete(token); return respond(res, 200, { success: true }); }
    if (method === 'GET' && route === '/api/auth/me') { const user = auth(req, res); if (user) respond(res, 200, { success: true, data: user }); return; }
    const user = auth(req, res); if (!user) return;
 main
    if (method === 'GET' && route === '/api/dashboard') return respond(res, 200, { success: true, data: dashboard() });
    if (method === 'GET' && route === '/api/people') return respond(res, 200, { success: true, data: listPeople() });
    if (method === 'POST' && route === '/api/people') { if (user.role !== 'admin') return error(res, 403, 'Réservé aux administrateurs.'); const input = await body(req); const problem = validatePerson(input); if (problem) return error(res, 400, problem); if (input.photoData && !/^data:image\/(jpeg|png);base64,/.test(input.photoData)) return error(res, 400, 'Format de photo invalide.'); const person = { id: id(), type: input.type, matricule: input.matricule.trim(), firstName: input.firstName.trim(), lastName: input.lastName.trim(), email: input.email?.trim() || '', faculty: input.faculty?.trim() || '', promotion: input.promotion?.trim() || '', department: input.department?.trim() || '', photoData: input.photoData || null, active: true }; db.people.push(person); const card = { id: id(), personId: person.id, qr: qrFor(person.type), status: 'active', issuedAt: now().slice(0, 10) }; db.cards.push(card); save(db); return respond(res, 201, { success: true, data: { ...person, card } }); }
    if (method === 'PATCH' && /^\/api\/people\/[^/]+$/.test(route)) { if (user.role !== 'admin') return error(res, 403, 'Réservé aux administrateurs.'); const target = findPerson(route.split('/').pop()); if (!target) return error(res, 404, 'Personne introuvable.'); const input = await body(req); Object.assign(target, ['firstName','lastName','email','faculty','promotion','department','active'].reduce((o,k) => (input[k] !== undefined && (o[k] = input[k]), o), {})); save(db); return respond(res, 200, { success: true, data: target }); }
    if (method === 'GET' && route === '/api/cards') return respond(res, 200, { success: true, data: db.cards.map(c => ({ ...c, person: findPerson(c.personId) && { ...findPerson(c.personId), name: personName(findPerson(c.personId)) } })) });
    if (method === 'PATCH' && /^\/api\/cards\/[^/]+$/.test(route)) { if (user.role !== 'admin') return error(res, 403, 'Réservé aux administrateurs.'); const target = db.cards.find(c => c.id === route.split('/').pop()); if (!target) return error(res, 404, 'Carte introuvable.'); const input = await body(req); if (!['active','inactive','blocked','lost'].includes(input.status)) return error(res, 400, 'Statut invalide.'); target.status = input.status; save(db); return respond(res, 200, { success: true, data: target }); }
    if (method === 'GET' && route === '/api/rooms') return respond(res, 200, { success: true, data: db.rooms });
    if (method === 'GET' && route === '/api/computers') return respond(res, 200, { success: true, data: db.computers.map(c => ({ ...c, room: db.rooms.find(r => r.id === c.roomId) })) });
    if (method === 'PATCH' && /^\/api\/computers\/[^/]+$/.test(route)) { if (user.role !== 'admin') return error(res, 403, 'Réservé aux administrateurs.'); const target = db.computers.find(c => c.id === route.split('/').pop()); const input = await body(req); if (!target) return error(res, 404, 'Poste introuvable.'); if (!['available','maintenance','out_of_service'].includes(input.status)) return error(res, 400, 'Statut invalide.'); if (target.status === 'occupied') return error(res, 409, 'Impossible de modifier un poste occupé.'); target.status = input.status; save(db); return respond(res, 200, { success: true, data: target }); }
    if (method === 'POST' && route === '/api/scans') { const input = await body(req); try { return respond(res, 200, { success: true, data: scan(String(input.qr || '').trim().toUpperCase(), input.roomId, input.computerId || 'private', user) }); } catch (e) { db.logs.push({ id: id(), action: 'refused', qr: input.qr || '', at: now(), agentId: user.id, message: e.message }); save(db); return error(res, 400, e.message); } }
    if (method === 'GET' && route === '/api/sessions') return respond(res, 200, { success: true, data: db.accessSessions.slice().reverse().map(enrichSession) });
    if (method === 'GET' && route === '/api/reservations') return respond(res, 200, { success: true, data: db.reservations.slice().reverse().map(r => ({ ...r, room: db.rooms.find(x => x.id === r.roomId), professor: findPerson(r.professorId) && { ...findPerson(r.professorId), name: personName(findPerson(r.professorId)) } })) });
    if (method === 'POST' && route === '/api/reservations') {
      const input = await body(req); const professor = findPerson(input.professorId); const room = db.rooms.find(r => r.id === input.roomId); if (!professor || professor.type !== 'professor' || !room) return error(res, 400, 'Professeur ou salle invalide.');
      if (!input.date || !input.startTime || !input.endTime) return error(res, 400, 'La période de réservation est incomplète.');
      const startMinutes = toMinutes(input.startTime); const endMinutes = toMinutes(input.endTime);
      if (startMinutes === null || endMinutes === null || endMinutes <= startMinutes) return error(res, 400, 'Heure de fin invalide : l’heure de fin doit être supérieure à l’heure de début.');
      const purpose = String(input.purpose || '').trim(); if (!purpose) return error(res, 400, 'Le motif de réservation est obligatoire.');
      const conflict = findReservationConflict(room.id, input.date, input.startTime, input.endTime);
      if (conflict) {
        const conflictProfessor = findPerson(conflict.professorId);
        const conflictDetails = conflictProfessor ? `${conflictProfessor.firstName} ${conflictProfessor.lastName}` : 'un autre professeur';
        return error(res, 409, `Conflit de réservation : la salle ${room.name} est déjà réservée le ${input.date} de ${conflict.startTime} à ${conflict.endTime} (${conflictDetails}).`);
      }
      const reservation = { id: id(), roomId: room.id, professorId: professor.id, date: input.date, startTime: input.startTime, endTime: input.endTime, purpose, status: 'pending', createdAt: now() };
      db.reservations.push(reservation); save(db); return respond(res, 201, { success: true, data: reservation });
    }
    if (method === 'PATCH' && /^\/api\/reservations\/[^/]+$/.test(route)) {
      const reservation = db.reservations.find(r => r.id === route.split('/').pop());
      const input = await body(req);
      if (!reservation) return error(res, 404, 'Réservation introuvable.');

      if (input.status !== undefined) {
        if (!['pending','confirmed','cancelled','completed'].includes(input.status)) return error(res, 400, 'Statut invalide.');
        reservation.status = input.status;
        save(db);
        return respond(res, 200, { success: true, data: reservation });
      }

      const roomId = input.roomId || reservation.roomId;
      const professorId = input.professorId || reservation.professorId;
      const date = input.date || reservation.date;
      const startTime = input.startTime || reservation.startTime;
      const endTime = input.endTime || reservation.endTime;
      const purpose = input.purpose !== undefined ? String(input.purpose).trim() : reservation.purpose;

      const room = db.rooms.find(r => r.id === roomId);
      if (!room) return error(res, 400, 'Salle invalide.');
      const professor = findPerson(professorId);
      if (!professor || professor.type !== 'professor') return error(res, 400, 'Professeur invalide.');

      const startMinutes = toMinutes(startTime);
      const endMinutes = toMinutes(endTime);
      if (startMinutes === null || endMinutes === null || endMinutes <= startMinutes) {
        return error(res, 400, 'Heure de fin invalide : l’heure de fin doit être supérieure à l’heure de début.');
      }
      if (!purpose) return error(res, 400, 'Le motif de réservation est obligatoire.');

      const conflict = findReservationConflict(roomId, date, startTime, endTime, reservation.id);
      if (conflict) {
        const conflictProfessor = findPerson(conflict.professorId);
        const details = conflictProfessor ? `${conflictProfessor.firstName} ${conflictProfessor.lastName}` : 'un autre professeur';
        return error(res, 409, `Conflit de réservation : la salle ${room.name} est déjà réservée le ${date} de ${conflict.startTime} à ${conflict.endTime} (${details}).`);
      }

      reservation.roomId = roomId;
      reservation.professorId = professorId;
      reservation.date = date;
      reservation.startTime = startTime;
      reservation.endTime = endTime;
      reservation.purpose = purpose;
      reservation.updatedAt = now();
      save(db);
      return respond(res, 200, { success: true, data: reservation });
    }

    if (method === 'GET' && route === '/api/dashboard') { if (!requirePermission(res, user, 'dashboard:read')) return; return respond(res, 200, { success: true, data: dashboard() }); }
    if (method === 'GET' && route === '/api/people') { if (!requirePermission(res, user, 'people:read')) return; return respond(res, 200, { success: true, data: listPeople() }); }
    if (method === 'POST' && route === '/api/people') { if (!requirePermission(res, user, 'people:manage')) return; const input = await body(req); const problem = validatePerson(input); if (problem) return error(res, 400, problem); if (input.photoData && !/^data:image\/(jpeg|png);base64,/.test(input.photoData)) return error(res, 400, 'Format de photo invalide.'); const person = { id: id(), type: input.type, matricule: input.matricule.trim(), firstName: input.firstName.trim(), lastName: input.lastName.trim(), email: input.email?.trim() || '', faculty: input.faculty?.trim() || '', promotion: input.promotion?.trim() || '', department: input.department?.trim() || '', photoData: input.photoData || null, active: true }; db.people.push(person); const card = { id: id(), personId: person.id, qr: qrFor(person.type), status: 'active', issuedAt: now().slice(0, 10) }; db.cards.push(card); save(db); return respond(res, 201, { success: true, data: { ...person, card } }); }
    if (method === 'PATCH' && /^\/api\/people\/[^/]+$/.test(route)) { if (!requirePermission(res, user, 'people:manage')) return; const target = findPerson(route.split('/').pop()); if (!target) return error(res, 404, 'Personne introuvable.'); const input = await body(req); Object.assign(target, ['firstName','lastName','email','faculty','promotion','department','active'].reduce((o,k) => (input[k] !== undefined && (o[k] = input[k]), o), {})); save(db); return respond(res, 200, { success: true, data: target }); }
    if (method === 'GET' && route === '/api/cards') { if (!requirePermission(res, user, 'cards:read')) return; return respond(res, 200, { success: true, data: db.cards.map(c => ({ ...c, person: findPerson(c.personId) && { ...findPerson(c.personId), name: personName(findPerson(c.personId)) } })) }); }
    if (method === 'PATCH' && /^\/api\/cards\/[^/]+$/.test(route)) { if (!requirePermission(res, user, 'cards:manage')) return; const target = db.cards.find(c => c.id === route.split('/').pop()); if (!target) return error(res, 404, 'Carte introuvable.'); const input = await body(req); if (!['active','inactive','blocked','lost'].includes(input.status)) return error(res, 400, 'Statut invalide.'); target.status = input.status; save(db); return respond(res, 200, { success: true, data: target }); }
    if (method === 'GET' && route === '/api/rooms') { if (!requirePermission(res, user, 'rooms:read')) return; return respond(res, 200, { success: true, data: db.rooms }); }
    if (method === 'GET' && route === '/api/computers') { if (!requirePermission(res, user, 'computers:read')) return; return respond(res, 200, { success: true, data: db.computers.map(c => ({ ...c, room: db.rooms.find(r => r.id === c.roomId) })) }); }
    if (method === 'PATCH' && /^\/api\/computers\/[^/]+$/.test(route)) { if (!requirePermission(res, user, 'computers:manage')) return; const target = db.computers.find(c => c.id === route.split('/').pop()); const input = await body(req); if (!target) return error(res, 404, 'Poste introuvable.'); if (!['available','maintenance','out_of_service'].includes(input.status)) return error(res, 400, 'Statut invalide.'); if (target.status === 'occupied') return error(res, 409, 'Impossible de modifier un poste occupé.'); target.status = input.status; save(db); return respond(res, 200, { success: true, data: target }); }
    if (method === 'POST' && route === '/api/scans') { if (!requirePermission(res, user, 'scans:create')) return; const input = await body(req); try { return respond(res, 200, { success: true, data: scan(String(input.qr || '').trim().toUpperCase(), input.roomId, input.computerId || 'private', user) }); } catch (e) { db.logs.push({ id: id(), action: 'refused', qr: input.qr || '', at: now(), agentId: user.id, message: e.message }); save(db); return error(res, 400, e.message); } }
    if (method === 'GET' && route === '/api/sessions') { if (!requirePermission(res, user, 'sessions:read')) return; return respond(res, 200, { success: true, data: db.accessSessions.slice().reverse().map(enrichSession) }); }
    if (method === 'GET' && route === '/api/access-logs') { if (!requirePermission(res, user, 'logs:read')) return; return respond(res, 200, { success: true, data: db.logs.slice().reverse() }); }
    if (method === 'GET' && route === '/api/reservations') { if (!requirePermission(res, user, 'reservations:read')) return; return respond(res, 200, { success: true, data: db.reservations.slice().reverse().map(r => ({ ...r, room: db.rooms.find(x => x.id === r.roomId), professor: findPerson(r.professorId) && { ...findPerson(r.professorId), name: personName(findPerson(r.professorId)) } })) }); }
    if (method === 'POST' && route === '/api/reservations') { if (!requirePermission(res, user, 'reservations:manage')) return; const input = await body(req); const professor = findPerson(input.professorId); const room = db.rooms.find(r => r.id === input.roomId); if (!professor || professor.type !== 'professor' || !room) return error(res, 400, 'Professeur ou salle invalide.'); if (!input.date || !input.startTime || !input.endTime || input.endTime <= input.startTime) return error(res, 400, 'La période de réservation est invalide.'); const conflict = db.reservations.find(r => r.roomId === input.roomId && r.date === input.date && r.status !== 'cancelled' && input.startTime < r.endTime && input.endTime > r.startTime); if (conflict) return error(res, 409, 'Conflit : cette salle est déjà réservée sur ce créneau.'); const reservation = { id: id(), roomId: room.id, professorId: professor.id, date: input.date, startTime: input.startTime, endTime: input.endTime, purpose: String(input.purpose || '').trim(), status: 'confirmed', createdAt: now() }; db.reservations.push(reservation); save(db); return respond(res, 201, { success: true, data: reservation }); }
    if (method === 'PATCH' && /^\/api\/reservations\/[^/]+$/.test(route)) { if (!requirePermission(res, user, 'reservations:manage')) return; const reservation = db.reservations.find(r => r.id === route.split('/').pop()); const input = await body(req); if (!reservation) return error(res, 404, 'Réservation introuvable.'); if (!['confirmed','cancelled','completed'].includes(input.status)) return error(res, 400, 'Statut invalide.'); reservation.status = input.status; save(db); return respond(res, 200, { success: true, data: reservation }); }main
    return error(res, 404, 'Route introuvable.');
  } catch (e) { console.error(e); error(res, e.status || 500, e.message || 'Erreur interne.'); }
});
if (require.main === module) {
  server.on('error', error => {
    if (error.code === 'EADDRINUSE') {
      console.error(`Le port ${PORT} est déjà utilisé. Fermez l’autre serveur ou lancez : $env:PORT=3001; node backend/server.js`);
    } else {
      console.error('Impossible de démarrer LabAccess :', error.message);
    }
    process.exitCode = 1;
  });
  server.listen(PORT, () => console.log(`LabAccess sur http://localhost:${PORT}`));
}
module.exports = { server, seed, scan };
