/**
 * ID CARD STUDIO — SINGLE-FILE EDITION
 * Includes all backend code and all HTML/CSS/browser scripts.
 * Keep your existing appsscript.json and Script Properties.
 * Replace Code.gs and remove the other application .gs files to avoid duplicate declarations.
 * The old HTML files are no longer required.
 * Deploy a new web-app version after saving.
 */


// ==================== AccessControl.gs ====================
/** Application access registry. Campus records and photos remain in User Properties. */
const ACCESS_ADMIN_PROPERTY_ = 'ID_STUDIO_ADMIN_EMAIL';
const ACCESS_USER_PREFIX_ = 'ID_STUDIO_ALLOWED_';
const ACCESS_USER_LIMIT_ = 1000;

function accessEmail_(value) {
  const email = String(value || '').trim().toLowerCase();
  if (email.length > 254 || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(email)) {
    throw new Error('Enter a valid Google account email address.');
  }
  return email;
}

function accessIdentity_() {
  const active = String(Session.getActiveUser().getEmail() || '').trim().toLowerCase();
  const effective = String(Session.getEffectiveUser().getEmail() || '').trim().toLowerCase();
  if (!active || active !== effective) {
    throw new Error('Sign in with your Google account. This app must execute as the user accessing it.');
  }
  return accessEmail_(active);
}

function accessAdmin_() {
  const value = PropertiesService.getScriptProperties().getProperty(ACCESS_ADMIN_PROPERTY_);
  if (!value) throw new Error('Access control is not configured. The project owner must set ID_STUDIO_ADMIN_EMAIL in Script Properties.');
  return accessEmail_(value);
}

function accessKey_(email) {
  return ACCESS_USER_PREFIX_ + encodeURIComponent(email);
}

function assertAppAccess_() {
  const email = accessIdentity_();
  const admin = accessAdmin_();
  if (email !== admin && PropertiesService.getScriptProperties().getProperty(accessKey_(email)) !== 'enabled') {
    throw new Error('Access denied. Contact the application administrator to request access for your Google account.');
  }
  return { email: email, isAdmin: email === admin };
}

function assertAdminAccess_() {
  const email = accessIdentity_();
  if (email !== accessAdmin_()) throw new Error('Administrator access is required.');
  return email;
}

/** Authorize inside the lock so a transferred administrator cannot perform queued writes. */
function accessAdminWrite_(operation) {
  assertAdminAccess_();
  const lock = LockService.getScriptLock();
  lock.waitLock(30000);
  try {
    const administrator = assertAdminAccess_();
    return operation(PropertiesService.getScriptProperties(), administrator);
  } finally {
    lock.releaseLock();
  }
}

function accessUsers_(properties, administrator) {
  const all = properties.getProperties();
  return Object.keys(all).filter(key => key.indexOf(ACCESS_USER_PREFIX_) === 0).map(key => {
    let email;
    try { email = accessEmail_(decodeURIComponent(key.slice(ACCESS_USER_PREFIX_.length))); }
    catch (error) { return null; }
    return {email: email, enabled: all[key] === 'enabled'};
  }).filter(user => user && user.email !== administrator).sort((a, b) => a.email.localeCompare(b.email));
}

function adminListUsers() {
  const administrator = assertAdminAccess_();
  return {
    administrator: administrator,
    users: accessUsers_(PropertiesService.getScriptProperties(), administrator),
    limit: ACCESS_USER_LIMIT_
  };
}

/** Import adds missing accounts. It never silently re-enables an existing disabled account. */
function adminImportUsers(emails) {
  assertAdminAccess_();
  if (!Array.isArray(emails) || !emails.length || emails.length > 500) {
    throw new Error('Provide between 1 and 500 email addresses per import.');
  }
  const unique = Array.from(new Set(emails.map(accessEmail_)));
  return accessAdminWrite_((properties, administrator) => {
    const all = properties.getProperties();
    const additions = unique.filter(email => email !== administrator && !Object.prototype.hasOwnProperty.call(all, accessKey_(email)));
    const count = Object.keys(all).filter(key => key.indexOf(ACCESS_USER_PREFIX_) === 0).length;
    if (count + additions.length > ACCESS_USER_LIMIT_) throw new Error('The approved-user limit is 1,000. Remove unused accounts before adding more.');
    const changes = {};
    additions.forEach(email => { changes[accessKey_(email)] = 'enabled'; });
    if (additions.length) properties.setProperties(changes, false);
    return {added: additions.length, unchanged: unique.length - additions.length};
  });
}

function adminSetUserAccess(email, enabled) {
  assertAdminAccess_();
  const target = accessEmail_(email);
  if (typeof enabled !== 'boolean') throw new Error('Access must be enabled or disabled.');
  return accessAdminWrite_((properties, administrator) => {
    if (target === administrator) throw new Error('The administrator always has access. Use Change Administrator instead.');
    const key = accessKey_(target);
    if (properties.getProperty(key) === null) throw new Error('This account is no longer on the approved-user list. Refresh the list.');
    properties.setProperty(key, enabled ? 'enabled' : 'disabled');
    return {success: true};
  });
}

function adminRemoveUser(email) {
  assertAdminAccess_();
  const target = accessEmail_(email);
  return accessAdminWrite_((properties, administrator) => {
    if (target === administrator) throw new Error('The administrator cannot be removed. Use Change Administrator instead.');
    properties.deleteProperty(accessKey_(target));
    return {success: true};
  });
}

function adminTransferAccess(newEmail, confirmationEmail) {
  assertAdminAccess_();
  const target = accessEmail_(newEmail);
  if (target !== accessEmail_(confirmationEmail)) throw new Error('Both administrator email addresses must match.');
  return accessAdminWrite_((properties, administrator) => {
    if (target === administrator) throw new Error('That account is already the administrator.');
    const all = properties.getProperties();
    const count = Object.keys(all).filter(key => key.indexOf(ACCESS_USER_PREFIX_) === 0).length;
    if (!Object.prototype.hasOwnProperty.call(all, accessKey_(administrator)) && count >= ACCESS_USER_LIMIT_) {
      throw new Error('Remove an unused account before transferring administrator access.');
    }
    const changes = {};
    changes[ACCESS_ADMIN_PROPERTY_] = target;
    changes[accessKey_(administrator)] = 'enabled';
    properties.setProperties(changes, false);
    return {success: true};
  });
}

/** A denied request must not render studio templates or account data. */
function accessDeniedPage_() {
  return HtmlService.createHtmlOutput('<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access unavailable</title></head><body style="font:16px Arial,sans-serif;background:#eef2f7;color:#243247;padding:32px"><main style="max-width:540px;margin:8vh auto;padding:28px;background:white;border:1px solid #cbd5e1;border-radius:12px"><h1 style="font-size:24px">Access unavailable</h1><p>Sign in with an approved Google account. If you need access, contact the application administrator.</p><p>The project owner can also check the administrator setting and deployment configuration.</p></main></body></html>').setTitle('Access unavailable');
}


// ==================== UsageReports.gs ====================
/** Aggregate usage only. Never pass record data, source IDs, photos or designs here. */
const USAGE_PREFIX_ = 'ID_STUDIO_USAGE_V1_';
const USAGE_STUDIOS_ = ['student', 'staff', 'custom', 'design'];
const USAGE_ACCOUNT_LIMIT_ = 1000;

function usageEmpty_() {
  return {first: null, last: null, open: [0, 0, 0, 0], photo: [0, 0, 0], print: [0, 0, 0]};
}

function usageRead_(raw) {
  const row = usageEmpty_();
  if (!raw) return row;
  const data = JSON.parse(raw);
  ['first', 'last'].forEach(key => {
    if (typeof data[key] === 'string' && Number.isFinite(Date.parse(data[key]))) row[key] = data[key];
  });
  ['open', 'photo', 'print'].forEach(key => {
    row[key] = row[key].map((value, index) => {
      const count = data[key] && data[key][index];
      return Number.isSafeInteger(count) && count >= 0 ? count : 0;
    });
  });
  return row;
}

/** Best effort: an unavailable report must never prevent a card or photo operation. */
function usageRecord_(event, studio) {
  let lock;
  let locked = false;
  try {
    const access = assertAppAccess_();
    const index = USAGE_STUDIOS_.indexOf(studio);
    if (event !== 'visit' && (!['open', 'photo', 'print'].includes(event) || index < 0 || (event !== 'open' && index > 2))) return false;
    lock = LockService.getScriptLock();
    locked = lock.tryLock(1000);
    if (!locked) return false;
    assertAppAccess_();
    const properties = PropertiesService.getScriptProperties();
    const all = properties.getProperties();
    const key = USAGE_PREFIX_ + encodeURIComponent(access.email);
    // Leave space for the access registry and other application settings.
    if (!all[key] && (Object.keys(all).filter(k => k.startsWith(USAGE_PREFIX_)).length >= USAGE_ACCOUNT_LIMIT_ || JSON.stringify(all).length > 350000)) return false;
    const row = usageRead_(all[key]);
    const now = new Date().toISOString();
    row.first = row.first || now;
    row.last = now;
    if (event !== 'visit') row[event][index] += 1;
    properties.setProperty(key, JSON.stringify(row));
    return true;
  } catch (error) {
    // Do not log error payloads: they may contain data from upstream operations.
    return false;
  } finally {
    if (locked) {
      try { lock.releaseLock(); } catch (error) { /* Do not affect the original operation. */ }
    }
  }
}

/** Identity comes exclusively from the authenticated server session. */
function recordStudioPrintRequest(studio) {
  assertAppAccess_();
  if (!['student', 'staff', 'custom'].includes(studio)) throw new Error('Unknown card studio.');
  return {recorded: usageRecord_('print', studio)};
}

/** The report reads only the access registry and usage counters, never campus sources. */
function adminGetUsageReport() {
  const administrator = assertAdminAccess_();
  const all = PropertiesService.getScriptProperties().getProperties();
  const emails = new Set([administrator]);
  accessUsers_(PropertiesService.getScriptProperties(), administrator).forEach(user => emails.add(user.email));
  Object.keys(all).filter(key => key.startsWith(USAGE_PREFIX_)).forEach(key => {
    try { emails.add(accessEmail_(decodeURIComponent(key.slice(USAGE_PREFIX_.length)))); }
    catch (error) { /* Ignore malformed keys, never return arbitrary stored content. */ }
  });
  let unreadable = 0;
  const rows = Array.from(emails).map(email => {
    let usage;
    try { usage = usageRead_(all[USAGE_PREFIX_ + encodeURIComponent(email)]); }
    catch (error) { usage = usageEmpty_(); unreadable += 1; }
    const state = email === administrator ? 'Administrator' : all[accessKey_(email)] === 'enabled' ? 'Enabled' : all[accessKey_(email)] === 'disabled' ? 'Disabled' : 'Removed';
    return {email: email, access: state, first: usage.first, last: usage.last, openings: usage.open, photoSaves: usage.photo, printRequests: usage.print};
  });
  rows.sort((a, b) => String(b.last || '').localeCompare(String(a.last || '')) || a.email.localeCompare(b.email));
  return {generatedAt: new Date().toISOString(), rows: rows, unreadable: unreadable, trackedAccounts: rows.filter(row => row.first).length, accountLimit: USAGE_ACCOUNT_LIMIT_};
}

/** Clear one user's usage only; keep their approved-account status unchanged. */
function adminClearUsageReport(email, confirmation) {
  assertAdminAccess_();
  if (confirmation !== 'CLEAR_USER_USAGE') throw new Error('Select a user and confirm clearing their usage report first.');
  const target = accessEmail_(email);
  return accessAdminWrite_(properties => {
    const key = USAGE_PREFIX_ + encodeURIComponent(target);
    const existed = properties.getProperty(key) !== null;
    properties.deleteProperty(key);
    return {success: true, email: target, cleared: existed};
  });
}


// ==================== Reliability.gs ====================
/** ID Card Studio: dynamic designs, explicit column mappings, per-user sources. */

// Routing and per-user access

function clientStorageScope_(type) {
  const p = getCampusProperties_();
  let account = p.getProperty('BROWSER_SCOPE_ID');
  if (!account) {
    const lock = LockService.getUserLock();
    lock.waitLock(30000);
    try {
      account = p.getProperty('BROWSER_SCOPE_ID');
      if (!account) {
        account = Utilities.getUuid();
        p.setProperty('BROWSER_SCOPE_ID', account);
      }
    } finally {
      lock.releaseLock();
    }
  }
  let source = 'designer';
  if (['student', 'staff', 'custom'].includes(type)) {
    const id = p.getProperty(studioKeys_(type).sheet) || 'unconnected';
    source = type + '_' + id + '_' + (p.getProperty('worksheet_' + type + '_' + id) || 'default') + '_' + (p.getProperty(studioKeys_(type).folder) || '');
    if (id !== 'unconnected') {
      const selection = JSON.parse(p.getProperty('worksheet_' + type + '_' + id) || '{}');
      const schema = selection.sheetId === undefined ? null : JSON.parse(p.getProperty('schema_v2_' + id + '_' + selection.sheetId) || 'null');
      if (schema && schema.layoutRevision) source += '_' + schema.layoutRevision;
    }
  }
  return 'idstudio_v2_' + account + '_' + Utilities.base64EncodeWebSafe(source) + '_';
}

// Data-source configuration

/** Shared per-user spreadsheet schema and record identity. No browser identity is trusted. */
function studioKeys_(type) {
  if (!['student', 'staff', 'custom'].includes(type)) throw new Error('Unknown studio.');
  const prefix = type === 'student' ? 'ACTIVE_' : 'ACTIVE_' + type.toUpperCase() + '_';
  return {
    sheet: prefix + 'SPREADSHEET_ID',
    folder: prefix + 'PHOTO_FOLDER_ID'
  };
}
function studioContext_(type) {
  const p = getCampusProperties_();
  const keys = studioKeys_(type);
  const id = p.getProperty(keys.sheet);
  if (!id) throw new Error('Connect a spreadsheet in Data Sources first.');
  const book = SpreadsheetApp.openById(id);
  const selection = JSON.parse(p.getProperty('worksheet_' + type + '_' + id) || '{}');
  const sheet = selection.sheetId === undefined ? book.getSheets()[0] : book.getSheets().find(s => s.getSheetId() === Number(selection.sheetId));
  if (!sheet) throw new Error('The selected worksheet was removed. Choose a worksheet again.');
  const schemaKey = 'schema_v2_' + id + '_' + sheet.getSheetId();
  const schema = JSON.parse(p.getProperty(schemaKey) || 'null');
  return {
    type: type,
    p: p,
    keys: keys,
    id: id,
    book: book,
    sheet: sheet,
    schemaKey: schemaKey,
    schema: schema,
    header: !!selection.header,
    start: selection.header ? 2 : 1
  };
}
function connectStudioPhotoFolder_(type, url) {
  clientStorageScope_('design');
  const folderId = extractFolderId(url);
  if (!folderId) throw new Error('Enter a photo folder URL or ID.');
  DriveApp.getFolderById(folderId).getName();
  const p = getCampusProperties_();
  const keys = studioKeys_(type);
  const old = p.getProperty(keys.folder);
  const lock = LockService.getUserLock();
  lock.waitLock(30000);
  try {
    if (old !== folderId && p.getProperty(keys.sheet)) {
      const c = studioContext_(type);
      if (c.schema && c.sheet.getLastRow() >= c.start) c.sheet.getRange(c.start, c.schema.photoCol + 1, c.sheet.getLastRow() - c.start + 1, 1).clearContent();
    }
    p.setProperty(keys.folder, folderId);
    // Legacy photos are resolved by the next manifest and linked on mapping/edit.
    // Do not perform a fallible folder scan after committing the new source.
    return {
      success: true,
      scope: clientStorageScope_(type)
    };
  } finally {
    lock.releaseLock();
  }
}

// Worksheet selection and explicit column mapping

function getStudioSourceInfo(type) {
  assertAppAccess_();
  const c = studioContext_(type);
  if (!c.schema) {
    const info = getDesignMappingInfo(type);
    return {
      sheetId: info.sheetId,
      header: info.header,
      worksheets: info.worksheets,
      headers: info.columns.map(col => col.label),
      sampleRow: info.columns.map(col => col.sample),
      schemaReady: false
    };
  }
  const width = c.schema.dataWidth;
  const first = c.sheet.getRange(1, 1, 1, width).getDisplayValues()[0];
  return {
    sheetId: c.sheet.getSheetId(),
    header: c.header,
    worksheets: c.book.getSheets().map(sheet => ({
      id: sheet.getSheetId(),
      name: sheet.getName()
    })),
    headers: buildSpreadsheetColumnLabels_(width).map((label, index) => label + (c.header && first[index] ? ' — ' + first[index] : '')),
    sampleRow: c.sheet.getLastRow() >= c.start ? c.sheet.getRange(c.start, 1, 1, width).getDisplayValues()[0] : [],
    schemaReady: true
  };
}
function setStudioWorksheet(type, sheetId, header) {
  assertAppAccess_();
  const current = studioContext_(type);
  if (current.sheet.getSheetId() === Number(sheetId) && current.header === !!header) return getStudioSourceInfo(type);
  const fields = [];
  if (current.sheet.getSheetId() === Number(sheetId) && current.schema) {
    const reverse = {
      grade: 'class',
      transport: 'transportation'
    };
    Object.keys(current.schema.core).forEach(key => fields.push({
      type: reverse[key] || key,
      columnIndex: current.schema.core[key]
    }));
    current.schema.writable.forEach(index => {
      if (!fields.some(field => field.columnIndex === index)) fields.push({
        type: 'text',
        columnIndex: index
      });
    });
  }
  saveDesignMapping(type, {
    sheetId: sheetId,
    header: !!header,
    fields: fields
  });
  return getStudioSourceInfo(type);
}
function saveStudioSchema(type, fields) {
  assertAppAccess_();
  return saveDesignMapping(type, {
    fields: fields
  });
}

// Record validation, identity, and shared CRUD

function validateMappedIds_(c, index, excludeRow, newId) {
  if (!Number.isInteger(index)) return;
  const seen = Object.create(null);
  const values = c.sheet.getLastRow() >= c.start ? c.sheet.getRange(c.start, index + 1, c.sheet.getLastRow() - c.start + 1, 1).getDisplayValues() : [];
  values.forEach((row, i) => {
    if (i + c.start === excludeRow) return;
    const id = normalizeStudentId_(row[0]);
    if (!id) return;
    if (seen[id]) throw new Error('Duplicate Student ID ' + row[0] + ' in rows ' + seen[id] + ' and ' + (i + c.start) + '.');
    seen[id] = i + c.start;
  });
  if (newId !== undefined) {
    const key = normalizeStudentId_(newId);
    if (!key) return;
    if (seen[key]) throw new Error('A student already uses ID ' + newId + '.');
  }
}
function ensureRecordIds_(c) {
  assertStudioSchema_(c);
  const n = c.sheet.getLastRow() - c.start + 1;
  if (n <= 0) return;
  const values = c.sheet.getRange(c.start, 1, n, c.schema.photoCol + 1).getDisplayValues();
  const seen = Object.create(null);
  values.forEach((r, i) => {
    if (!r.slice(0, c.schema.dataWidth).some(v => String(v).trim())) return;
    let id = r[c.schema.uuidCol];
    if (id && seen[id]) throw new Error('Duplicate internal record ID. Restore the original row or remove the copied hidden ID before continuing.');
    if (!id) {
      id = Utilities.getUuid();
      c.sheet.getRange(c.start + i, c.schema.uuidCol + 1).setValue(id);
      if (r[c.schema.photoCol]) c.sheet.getRange(c.start + i, c.schema.photoCol + 1).clearContent();
    }
    seen[id] = true;
  });
}
function assertStudioSchema_(c) {
  const schema = c.schema;
  if (!schema || schema.photoCol >= c.sheet.getMaxColumns()) throw new Error('Record columns changed. Open Design Mapping and save to repair them.');
  const notes = c.sheet.getRange(1, schema.uuidCol + 1, 1, 2).getNotes()[0];
  if (!String(notes[0]).startsWith('ID Card Studio internal record identity.') || !String(notes[1]).startsWith('ID Card Studio photo file ID.')) throw new Error('Record columns moved or were removed. Open Design Mapping and save to repair them.');
}
function readStudioRecords_(type) {
  const c = studioContext_(type);
  const s = c.schema;
  if (!s) return [];
  const lock = LockService.getUserLock();
  lock.waitLock(30000);
  try {
    ensureRecordIds_(c);
  } finally {
    lock.releaseLock();
  }
  if (type === 'student') validateMappedIds_(c, s.core.idNumber);
  const width = s.photoCol + 1;
  const n = c.sheet.getLastRow() - c.start + 1;
  const headers = getStudioSourceInfo(type).headers;
  return (n > 0 ? c.sheet.getRange(c.start, 1, n, width).getDisplayValues() : []).map((r, i) => {
    if (!r.slice(0, s.dataWidth).some(v => String(v).trim())) return null;
    const value = key => s.core[key] === undefined ? '' : String(r[s.core[key]] || '').trim();
    const record = {
      recordKey: r[s.uuidCol],
      _photoFileId: r[s.photoCol] || '',
      _sheetRow: i + c.start,
      _row: r.slice(0, s.dataWidth),
      _headers: headers
    };
    Object.keys(s.core).forEach(key => {
      record[key] = value(key);
    });
    return record;
  }).filter(Boolean);
}
function studioResult_(type, key) {
  const data = readStudioRecords_(type);
  return type === 'student' ? {
    success: true,
    savedId: key,
    students: data
  } : type === 'staff' ? {
    success: true,
    savedKey: key,
    staff: data
  } : {
    success: true,
    savedKey: key,
    records: data
  };
}
function changeStudioRecord_(type, record, originalKey, remove) {
  const lock = LockService.getUserLock();
  lock.waitLock(30000);
  let savedKey;
  try {
    const c = studioContext_(type);
    const s = c.schema;
    if (!s) throw new Error('Save your worksheet and column mapping before editing records.');
    ensureRecordIds_(c);
    if (originalKey) migrateLegacyPhotos_(c);
    const rows = c.sheet.getLastRow() >= c.start ? c.sheet.getRange(c.start, 1, c.sheet.getLastRow() - c.start + 1, s.photoCol + 1).getDisplayValues() : [];
    const indexedRows = rows.map((r, i) => ({
      r: r,
      i: i
    }));
    let matches = originalKey ? indexedRows.filter(x => x.r[s.uuidCol] === originalKey) : [];
    // Compatibility with a still-open older Student page. UUID always wins.
    if (originalKey && !matches.length && type === 'student' && Number.isInteger(s.core.idNumber)) {
      matches = indexedRows.filter(x => normalizeStudentId_(x.r[s.core.idNumber]) === normalizeStudentId_(originalKey));
    }
    if (originalKey && matches.length !== 1) throw new Error('The record changed or no longer exists. Refresh the studio before editing.');
    const old = matches.length ? matches[0].r : null;
    const rowNumber = old ? matches[0].i + c.start : Math.max(c.start, c.sheet.getLastRow() + 1);
    if (remove) {
      // Trash only the explicitly linked photo. Unlinked name-based files are left intact.
      if (old[s.photoCol] && rows.filter(r => r[s.photoCol] === old[s.photoCol]).length === 1) {
        const file = checkedStudioPhotoFile_(type, old[s.photoCol]);
        file.setTrashed(true);
      }
      c.sheet.deleteRow(rowNumber);
      savedKey = '';
    } else {
      const values = record && record.columnValues;
      if (!values || typeof values !== 'object') throw new Error('Use the mapped record form.');
      const draft = old ? old.slice() : new Array(s.photoCol + 1).fill('');
      const changes = [];
      Object.keys(values).forEach(key => {
        const index = Number(key);
        if (!Number.isInteger(index) || !s.writable.includes(index)) throw new Error('Column mapping changed. Reopen the record form.');
        const value = String(values[key] == null ? '' : values[key]);
        if (value.length > 50000) throw new Error('A field is too long.');
        draft[index] = value;
        changes.push({
          index: index,
          value: value
        });
      });
      if (!draft.slice(0, s.dataWidth).some(v => String(v).trim())) throw new Error('Enter record data first.');
      if (type === 'student') validateMappedIds_(c, s.core.idNumber, old ? rowNumber : null, draft[s.core.idNumber]);
      if (!old) {
        draft[s.uuidCol] = Utilities.getUuid();
        c.sheet.getRange(rowNumber, 1, 1, draft.length).setNumberFormat('@').setValues([draft.map(literalCell_)]);
      } else changes.forEach(change => c.sheet.getRange(rowNumber, change.index + 1).setNumberFormat('@').setValue(literalCell_(change.value)));
      const sortColumn = s.core.firstName !== undefined ? s.core.firstName : s.core.fullName;
      if (sortColumn !== undefined && c.sheet.getLastRow() > c.start) c.sheet.getRange(c.start, 1, c.sheet.getLastRow() - c.start + 1, s.photoCol + 1).sort({
        column: sortColumn + 1,
        ascending: true
      });
      savedKey = draft[s.uuidCol];
    }
    SpreadsheetApp.flush();
  } finally {
    lock.releaseLock();
  }
  return studioResult_(type, savedKey);
}
function literalCell_(value) {
  const text = String(value == null ? '' : value);
  return text.startsWith('=') ? "'" + text : text;
}

// Shared photo lookup and storage

/** File names are optional labels; UUID and Drive file ID provide identity. */
function legacyPhotoName_(type, record) {
  const first = String(record.firstName || '').trim();
  const last = String(record.lastName || '').trim();
  const name = first && last ? first + ' ' + last : record.fullName || first || last;
  return String(type === 'student' ? record.idNumber || '' : name || '').trim().replace(/\s+/g, ' ');
}

/** Link only unique existing filenames. Never rename or delete legacy files during migration. Caller holds the write lock. */
function migrateLegacyPhotos_(c) {
  const s = c.schema;
  const folderId = c.p.getProperty(c.keys.folder);
  const n = c.sheet.getLastRow() - c.start + 1;
  if (!folderId || n <= 0) return;
  const rows = c.sheet.getRange(c.start, 1, n, s.photoCol + 1).getDisplayValues();
  const counts = Object.create(null);
  const names = rows.map(r => {
    const value = k => s.core[k] === undefined ? '' : String(r[s.core[k]] || '').trim();
    const name = legacyPhotoName_(c.type, {
      idNumber: value('idNumber'),
      fullName: value('fullName'),
      firstName: value('firstName'),
      lastName: value('lastName')
    }).toLowerCase();
    if (name) counts[name] = (counts[name] || 0) + 1;
    return name;
  });
  if (!rows.some((r, i) => names[i] && !r[s.photoCol])) return;
  const byName = Object.create(null);
  const files = DriveApp.getFolderById(folderId).getFiles();
  while (files.hasNext()) {
    const f = files.next();
    if (!/^image\//.test(f.getMimeType())) continue;
    const name = f.getName().replace(/\.[^.]+$/, '').trim().replace(/\s+/g, ' ').toLowerCase();
    (byName[name] || (byName[name] = [])).push(f.getId());
  }
  rows.forEach((r, i) => {
    const name = names[i];
    const matches = byName[name] || [];
    if (name && !r[s.photoCol] && counts[name] === 1 && matches.length === 1) c.sheet.getRange(c.start + i, s.photoCol + 1).setValue(matches[0]);
  });
}
function checkedStudioPhotoFile_(type, fileId) {
  const folderId = getCampusProperties_().getProperty(studioKeys_(type).folder);
  if (!folderId) throw new Error('Connect a photo folder first.');
  const file = DriveApp.getFileById(fileId);
  const parents = file.getParents();
  let found = false;
  while (parents.hasNext()) if (parents.next().getId() === folderId) found = true;
  if (!found || file.isTrashed()) throw new Error('Photo is unavailable in the connected folder.');
  return file;
}
function getStudioPhotoManifest(type, keys) {
  assertAppAccess_();
  const c = studioContext_(type);
  const folderId = c.p.getProperty(c.keys.folder);
  if (!folderId) throw new Error('Connect a photo folder first.');
  const records = readStudioRecords_(type);
  let files;
  try {
    files = DriveApp.getFolderById(folderId).getFiles();
  } catch (error) {
    throw new Error('The connected photo folder is unavailable. Reconnect the Photo Folder in Data Sources using a folder accessible to your signed-in Google account.');
  }
  const byName = Object.create(null);
  const byId = Object.create(null);
  const counts = Object.create(null);
  records.forEach(r => {
    const name = legacyPhotoName_(type, r).toLowerCase();
    counts[name] = (counts[name] || 0) + 1;
  });
  while (files.hasNext()) {
    const file = files.next();
    if (!/^image\//.test(file.getMimeType())) continue;
    const entry = {
      fileId: file.getId(),
      updated: file.getLastUpdated().getTime()
    };
    const name = file.getName().replace(/\.[^.]+$/, '').trim().replace(/\s+/g, ' ').toLowerCase();
    byId[entry.fileId] = entry;
    (byName[name] || (byName[name] = [])).push(entry);
  }
  return (keys || []).map(key => {
    const record = records.find(r => r.recordKey === String(key) || type === 'student' && r.idNumber && r.idNumber === String(key));
    if (!record) return {
      key: key,
      status: 'failed',
      error: 'Record not found'
    };
    let entry = record._photoFileId ? byId[record._photoFileId] : null;
    if (!entry) {
      const name = legacyPhotoName_(type, record).toLowerCase();
      const matches = byName[name] || [];
      if (matches.length > 1 || matches.length && counts[name] > 1) return {
        key: key,
        status: 'failed',
        error: 'Ambiguous full name or duplicate photo. Take a photo for this record.'
      };
      entry = matches[0];
      if (entry && records.some(other => other.recordKey !== record.recordKey && other._photoFileId === entry.fileId)) return {
        key: key,
        status: 'failed',
        error: 'This photo is linked to another record. Take a photo for this record.'
      };
    }
    return entry ? {
      key: key,
      status: 'ready',
      fileId: entry.fileId,
      updated: entry.updated
    } : {
      key: key,
      status: 'missing'
    };
  });
}
function getStudioPhotoFile(type, fileId) {
  assertAppAccess_();
  const file = checkedStudioPhotoFile_(type, fileId);
  const cache = CacheService.getUserCache();
  const key = 'photo-v2-' + fileId + '-' + file.getLastUpdated().getTime();
  let data = cache.get(key);
  if (data) return data;
  let blob;
  try {
    blob = file.getThumbnail();
  } catch (e) {}
  if (!blob) blob = file.getBlob();
  data = 'data:' + blob.getContentType() + ';base64,' + Utilities.base64Encode(blob.getBytes());
  if (data.length < 90000) cache.put(key, data, 21600);
  return data;
}
function saveStudioPhoto_(type, dataUrl, key) {
  if (typeof dataUrl !== 'string' || dataUrl.length > 14000000 || !/^data:image\/(jpeg|png);base64,[A-Za-z0-9+/=]+$/.test(dataUrl)) throw new Error('Invalid photo. Capture a JPEG or PNG image again.');
  const records = readStudioRecords_(type);
  const record = records.find(r => r.recordKey === String(key) || type === 'student' && r.idNumber && r.idNumber === String(key));
  if (!record) throw new Error('Select a current record first.');
  const lock = LockService.getUserLock();
  lock.waitLock(30000);
  try {
    const c = studioContext_(type);
    const s = c.schema;
    const folderId = c.p.getProperty(c.keys.folder);
    if (!folderId) throw new Error('Connect a photo folder first.');
    // Re-find by UUID under the write lock; sorting or an edit cannot redirect the save.
    const ids = c.sheet.getRange(c.start, s.uuidCol + 1, c.sheet.getLastRow() - c.start + 1, 1).getDisplayValues();
    const offset = ids.findIndex(r => r[0] === record.recordKey);
    if (offset < 0) throw new Error('Record was removed.');
    const folder = DriveApp.getFolderById(folderId);
    const mime = dataUrl.slice(5, dataUrl.indexOf(';'));
    const name = (legacyPhotoName_(type, record) || record.recordKey).replace(/[\\/\x00-\x1f]/g, '_') + (mime === 'image/png' ? '.png' : '.jpg');
    const file = folder.createFile(Utilities.newBlob(Utilities.base64Decode(dataUrl.split(',')[1]), mime, name));
    try {
      c.sheet.getRange(c.start + offset, s.photoCol + 1).setValue(file.getId());
      SpreadsheetApp.flush();
    } catch (e) {
      file.setTrashed(true);
      throw e;
    }
    if (record._photoFileId && record._photoFileId !== file.getId() && !records.some(r => r.recordKey !== record.recordKey && r._photoFileId === record._photoFileId)) {
      try {
        checkedStudioPhotoFile_(type, record._photoFileId).setTrashed(true);
      } catch (e) {
        Logger.log('Old photo retained: ' + e.message);
      }
    }
    return {
      success: true,
      fileName: name,
      fileId: file.getId()
    };
  } finally {
    lock.releaseLock();
  }
}

/** Preview a source without committing it. Cancel leaves the current studio intact. */
function designMappingContext_(type, spreadsheetUrl, sheetId, header) {
  const p = getCampusProperties_();
  const keys = studioKeys_(type);
  const id = spreadsheetUrl ? extractSheetId(spreadsheetUrl) : p.getProperty(keys.sheet);
  if (!id) throw new Error('Enter a spreadsheet URL in Data Sources first.');
  const book = SpreadsheetApp.openById(id);
  const selection = JSON.parse(p.getProperty('worksheet_' + type + '_' + id) || '{}');
  const explicitSheet = sheetId !== undefined && sheetId !== null && sheetId !== '';
  const selectedId = explicitSheet ? Number(sheetId) : selection.sheetId;
  const sheet = book.getSheets().find(item => item.getSheetId() === Number(selectedId)) || (!explicitSheet ? book.getSheets()[0] : null);
  if (!sheet) throw new Error('Worksheet not found. Select an available worksheet in Design Mapping.');
  const hasHeader = typeof header === 'boolean' ? header : !!selection.header;
  const schemaKey = 'schema_v2_' + id + '_' + sheet.getSheetId();
  return {
    type: type,
    p: p,
    keys: keys,
    id: id,
    book: book,
    sheet: sheet,
    schemaKey: schemaKey,
    schema: JSON.parse(p.getProperty(schemaKey) || 'null'),
    header: hasHeader,
    start: hasHeader ? 2 : 1
  };
}

/** Recognize only our marked columns. Never guess from arbitrary user headings. */
function inspectStudioColumns_(c) {
  const width = Math.max(1, c.sheet.getLastColumn());
  const height = Math.max(1, c.sheet.getLastRow());
  const range = c.sheet.getRange(1, 1, height, width);
  const values = range.getDisplayValues();
  const formulas = range.getFormulas();
  const notes = c.sheet.getRange(1, 1, 1, width).getNotes()[0];
  const uuid = [];
  const photo = [];
  const data = [];
  for (let index = 0; index < width; index++) {
    const heading = values[0][index];
    const note = notes[index] || '';
    if (heading === '_ID_CARD_RECORD_UUID' || note.startsWith('ID Card Studio internal record identity.')) uuid.push(index);else if (heading === '_ID_CARD_PHOTO_FILE_ID' || note.startsWith('ID Card Studio photo file ID.')) photo.push(index);else data.push(index);
  }
  // Trailing empty cells from the old fixed-width implementation are not data.
  while (data.length && !values.some((row, i) => String(row[data[data.length - 1]] || '').trim() || formulas[i][data[data.length - 1]]) && !notes[data[data.length - 1]]) data.pop();
  if (!data.length) data.push(0);
  const internal = uuid.concat(photo).sort((a, b) => a - b);
  const remap = {};
  data.forEach(index => {
    remap[index] = index - internal.filter(col => col < index).length;
  });
  return {
    values: values,
    uuid: uuid,
    photo: photo,
    internal: internal,
    data: data,
    remap: remap,
    dataWidth: Math.max(1, ...data.map(index => remap[index] + 1))
  };
}
function getDesignMappingInfo(type, spreadsheetUrl, sheetId, header) {
  assertAppAccess_();
  const c = designMappingContext_(type, spreadsheetUrl, sheetId, header);
  const layout = inspectStudioColumns_(c);
  return {
    spreadsheetId: c.id,
    sheetId: c.sheet.getSheetId(),
    header: c.header,
    scope: clientStorageScopeForContext_(c),
    worksheets: c.book.getSheets().map(sheet => ({
      id: sheet.getSheetId(),
      name: sheet.getName()
    })),
    columns: layout.data.map(index => ({
      index: index,
      label: 'Column ' + spreadsheetColumnLetter_(index) + (c.header && layout.values[0][index] ? ' — ' + layout.values[0][index] : ''),
      sample: String((layout.values[c.start - 1] || [])[index] || '')
    })),
    layoutToken: JSON.stringify({
      sheet: c.sheet.getSheetId(),
      columns: layout.data,
      internal: layout.internal,
      header: c.header
    }),
    schemaReady: !!c.schema
  };
}

/** Canonicalize metadata once; preserve all user cells and existing photo links. */
function repairStudioColumns_(c, layout, regenerate) {
  const preferred = (columns, key) => columns.includes(c.schema && c.schema[key]) ? [c.schema[key]].concat(columns.filter(index => index !== c.schema[key])) : columns;
  const uuidColumns = preferred(layout.uuid, 'uuidCol');
  const photoColumns = preferred(layout.photo, 'photoCol');
  const seen = new Set();
  const metadata = layout.values.map((row, index) => {
    if (c.header && index === 0) return ['_ID_CARD_RECORD_UUID', '_ID_CARD_PHOTO_FILE_ID'];
    if (!layout.data.some(col => String(row[col] || '').trim())) return ['', ''];
    const photos = Array.from(new Set(photoColumns.map(col => row[col]).filter(Boolean)));
    if (photos.length > 1) throw new Error('Conflicting photo links in row ' + (index + 1) + '. Keep the correct link in the internal photo columns, then save Design Mapping again.');
    let uuid = uuidColumns.map(col => row[col]).find(value => value && value !== '_ID_CARD_RECORD_UUID');
    if (regenerate || !uuid || seen.has(uuid)) uuid = Utilities.getUuid();
    seen.add(uuid);
    return [uuid, photos[0] === '_ID_CARD_PHOTO_FILE_ID' ? '' : photos[0] || ''];
  });
  const canonical = layout.uuid.length === 1 && layout.photo.length === 1 && layout.uuid[0] === layout.dataWidth && layout.photo[0] === layout.dataWidth + 1;
  if (!canonical) {
    // Only columns carrying app-owned labels/notes are removed. Deleting in
    // reverse order preserves all user data, formulas, formatting and notes.
    layout.internal.slice().reverse().forEach(index => c.sheet.deleteColumns(index + 1, 1));
  }
  const required = layout.dataWidth + 2;
  if (c.sheet.getMaxColumns() < required) c.sheet.insertColumnsAfter(c.sheet.getMaxColumns(), required - c.sheet.getMaxColumns());
  c.sheet.getRange(1, layout.dataWidth + 1, metadata.length, 2).setNumberFormat('@').setValues(metadata);
  c.sheet.getRange(1, layout.dataWidth + 1).setNote('ID Card Studio internal record identity. Keep this column with its row when sorting.');
  c.sheet.getRange(1, layout.dataWidth + 2).setNote('ID Card Studio photo file ID. Do not edit.');
  c.sheet.hideColumns(layout.dataWidth + 1, 2);
  return {
    dataWidth: layout.dataWidth,
    uuidCol: layout.dataWidth,
    photoCol: layout.dataWidth + 1,
    layoutRevision: regenerate || layout.data.some(col => layout.remap[col] !== col) ? Utilities.getUuid() : c.schema && c.schema.layoutRevision || ''
  };
}
function clientStorageScopeForContext_(c) {
  const account = c.p.getProperty('BROWSER_SCOPE_ID');
  // Initialize the account namespace using the same guarded path as doGet.
  if (!account) clientStorageScope_('design');
  const selection = JSON.stringify({
    sheetId: c.sheet.getSheetId(),
    header: c.header
  });
  const source = c.type + '_' + c.id + '_' + selection + '_' + (c.p.getProperty(c.keys.folder) || '') + (c.schema && c.schema.layoutRevision ? '_' + c.schema.layoutRevision : '');
  return 'idstudio_v2_' + c.p.getProperty('BROWSER_SCOPE_ID') + '_' + Utilities.base64EncodeWebSafe(source) + '_';
}
function saveDesignMapping(type, settings) {
  assertAppAccess_();
  if (!settings || !Array.isArray(settings.fields)) throw new Error('Invalid design mapping.');
  // Initialize before acquiring the write lock to avoid recursive locking.
  clientStorageScope_('design');
  const lock = LockService.getUserLock();
  lock.waitLock(30000);
  try {
    const c = designMappingContext_(type, settings.spreadsheetUrl, settings.sheetId, settings.header);
    const layout = inspectStudioColumns_(c);
    const token = JSON.stringify({
      sheet: c.sheet.getSheetId(),
      columns: layout.data,
      internal: layout.internal,
      header: c.header
    });
    if (settings.layoutToken && settings.layoutToken !== token) throw new Error('Worksheet columns changed. Reopen Design Mapping to review the current columns.');
    const roleTypes = {
      firstName: 'firstName',
      lastName: 'lastName',
      fullName: 'fullName',
      class: 'grade',
      idNumber: 'idNumber',
      title: 'title',
      barcodeNumber: 'barcodeNumber',
      transportation: 'transport'
    };
    const core = {};
    const fields = settings.fields.map(field => {
      const index = Number(field.columnIndex);
      if (!Number.isInteger(index) || !layout.data.includes(index)) throw new Error('Choose an existing data column for each mapped element.');
      const role = roleTypes[field.type];
      if (role && core[role] === undefined) core[role] = index;
      return {
        id: String(field.id || ''),
        type: field.type,
        columnIndex: layout.remap[index]
      };
    });
    if (c.schema) Object.keys(c.schema.core || {}).forEach(role => {
      if (core[role] === undefined && layout.data.includes(c.schema.core[role])) core[role] = c.schema.core[role];
    });
    if (type === 'student' && Number.isInteger(core.idNumber)) validateMappedIds_(c, core.idNumber);
    // Resolve existing full-name/ID photos before a reset can change identity.
    if (c.schema && layout.uuid.includes(c.schema.uuidCol) && layout.photo.includes(c.schema.photoCol)) {
      try {
        migrateLegacyPhotos_(c);
      } catch (error) {
        Logger.log(error.message);
      }
      const refreshed = inspectStudioColumns_(c);
      layout.values = refreshed.values;
    }
    const schema = repairStudioColumns_(c, layout, false);
    schema.core = {};
    Object.keys(core).forEach(role => {
      schema.core[role] = layout.remap[core[role]];
    });
    schema.writable = Array.from(new Set(fields.map(field => field.columnIndex)));
    c.schema = schema;
    c.p.setProperty(c.schemaKey, JSON.stringify(schema));
    c.p.setProperty('worksheet_' + type + '_' + c.id, JSON.stringify({
      sheetId: c.sheet.getSheetId(),
      header: c.header
    }));
    c.p.setProperty(c.keys.sheet, c.id);
    SpreadsheetApp.flush();
    // Filename migration is retriable; a failure must not undo a saved setup.
    try {
      migrateLegacyPhotos_(c);
    } catch (error) {
      Logger.log(error.message);
    }
    return {
      success: true,
      scope: clientStorageScopeForContext_(c),
      fields: fields
    };
  } finally {
    lock.releaseLock();
  }
}
function resetStudioRecordCodes(type) {
  assertAppAccess_();
  clientStorageScope_('design');
  const lock = LockService.getUserLock();
  lock.waitLock(30000);
  try {
    const p = getCampusProperties_();
    if (!p.getProperty(studioKeys_(type).sheet)) return {
      success: true
    };
    const c = studioContext_(type);
    const layout = inspectStudioColumns_(c);
    if (!c.schema && !layout.internal.length) return {
      success: true
    };
    const oldCore = c.schema && c.schema.core || {};
    const schema = repairStudioColumns_(c, layout, true);
    schema.core = {};
    Object.keys(oldCore).forEach(role => {
      if (layout.data.includes(oldCore[role])) schema.core[role] = layout.remap[oldCore[role]];
    });
    schema.writable = [];
    c.p.setProperty(c.schemaKey, JSON.stringify(schema));
    return {
      success: true
    };
  } finally {
    lock.releaseLock();
  }
}


// ==================== Code.gs ====================
/** ID Card Studio: dynamic designs, explicit column mappings, per-user sources. */

// Routing and per-user access

/**
 * Serves the HTML UI.
 */
function studioTabRoute_(parameters) {
  const screen = String(parameters.screen || '').trim().toLowerCase();
  const studio = String(parameters.studio || parameters.page || parameters.mode || '').trim().toLowerCase();
  if (studio === 'control-center' || screen === 'control-center') return 'control-center';
  if (studio === 'student' || screen === 'student-studio') return 'student';
  if (studio === 'staff' || screen === 'staff-studio') return 'staff';
  if (studio === 'custom' || screen === 'custom-studio') return 'custom';
  if (studio === 'design' || screen === 'card-designer-v3' || screen === 'design-studio') return 'design';
  return 'student';
}

function doGet(e) {
  const initialTab = studioTabRoute_(e && e.parameter ? e.parameter : {});
  let access;
  try {
    access = assertAppAccess_();
    if (initialTab === 'control-center') assertAdminAccess_();
  } catch (error) {
    return accessDeniedPage_();
  }
  const template = studioEmbeddedTemplate_('StudioTabs');
  template.isAdministrator = access.isAdmin;
  template.initialTab = initialTab;
  const output = template.evaluate().setTitle('ID Card Studio').setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
  usageRecord_('visit', 'landing');
  return output;
}

/** Render only named studios for the authenticated tab host. No arbitrary file reads. */
function getStudioTabHtml(studio) {
  const access = assertAppAccess_();
  const files = {student: 'Student', staff: 'Staff', custom: 'Custom', design: 'Design', 'control-center': 'ControlCenter'};
  if (typeof studio !== 'string' || !Object.prototype.hasOwnProperty.call(files, studio)) throw new Error('Unknown studio.');
  if (studio === 'control-center') assertAdminAccess_();
  const template = studioEmbeddedTemplate_(files[studio]);
  template.webAppUrl = ScriptApp.getService().getUrl();
  template.isAdministrator = access.isAdmin;
  template.clientScope = clientStorageScope_(files[studio].toLowerCase());
  template.studioType = files[studio].toLowerCase();
  const bridge = studioEmbeddedTemplate_('StudioTabBridge').getRawContent();
  const html = template.evaluate().getContent().replace(/<head\b[^>]*>/i, head => head + '\n' + bridge);
  if (studio !== 'control-center') usageRecord_('open', studio);
  return {studio: studio, html: html};
}

function getStudioTabsAccess() {
  const access = assertAppAccess_();
  return {isAdministrator: access.isAdmin};
}

/** Includes a shared HTML/CSS/JavaScript partial in an evaluated page. */
function include(fileName) {
  assertAppAccess_();
  if (!['DesignRuntime', 'ReliabilityClient', 'DesignHistory'].includes(fileName)) throw new Error('Unsupported include.');
  return studioEmbeddedTemplate_(fileName).getRawContent();
}

/**
 * Returns configuration storage belonging only to the signed-in web-app user.
 *
 * Every campus uses its own Google account, spreadsheet, and photo folders.
 * User Properties prevent one campus from reading or replacing another
 * campus's saved Student, Staff, or Custom data-source IDs.
 */
function getCampusProperties_() {
  assertAppAccess_();
  const active = Session.getActiveUser().getEmail();
  const effective = Session.getEffectiveUser().getEmail();
  if (!active || !effective || active.toLowerCase() !== effective.toLowerCase()) throw new Error('Deploy this web app to execute as the user accessing it, then sign in with your campus Google account.');
  return PropertiesService.getUserProperties();
}


// Data-source configuration

/** Shared configuration operations. Public studio functions above are API adapters. */
function studioConfiguration_(type) {
  const properties = getCampusProperties_();
  const keys = studioKeys_(type);
  return {
    hasSpreadsheet: Boolean(properties.getProperty(keys.sheet)),
    hasPhotoFolder: Boolean(properties.getProperty(keys.folder))
  };
}

/**
 * Returns only the setup state, never the saved Drive or Spreadsheet IDs.
 */
function getAppConfiguration() {
  assertAppAccess_();
  return studioConfiguration_('student');
}

/** Returns the saved setup state for the Staff ID Card Studio. */
function getStaffConfiguration() {
  assertAppAccess_();
  return studioConfiguration_('staff');
}

/** Returns the saved setup state for the independent Custom ID Card Studio. */
function getCustomConfiguration() {
  assertAppAccess_();
  return studioConfiguration_('custom');
}

/**
 * Returns the browser URL for a configured Student, Staff, or Custom resource.
 * Only the explicitly supported per-user properties can be requested.
 */
function getConfiguredResourceUrl(cardType, resourceType) {
  assertAppAccess_();
  const type = String(cardType || '').toLowerCase();
  const resource = String(resourceType || '').toLowerCase();
  const propertyMap = {
    student: {
      spreadsheet: 'ACTIVE_SPREADSHEET_ID',
      folder: 'ACTIVE_PHOTO_FOLDER_ID'
    },
    staff: {
      spreadsheet: 'ACTIVE_STAFF_SPREADSHEET_ID',
      folder: 'ACTIVE_STAFF_PHOTO_FOLDER_ID'
    },
    custom: {
      spreadsheet: 'ACTIVE_CUSTOM_SPREADSHEET_ID',
      folder: 'ACTIVE_CUSTOM_PHOTO_FOLDER_ID'
    }
  };
  if (!propertyMap[type] || !propertyMap[type][resource]) {
    throw new Error('Unsupported card type or resource type.');
  }
  const savedId = getCampusProperties_().getProperty(propertyMap[type][resource]);
  if (!savedId) {
    throw new Error(resource === 'spreadsheet' ? 'No spreadsheet is connected. Open Data Sources and connect a spreadsheet URL or ID.' : 'No photo folder is connected. Open Data Sources and connect a Google Drive folder URL or ID.');
  }
  return resource === 'spreadsheet' ? 'https://docs.google.com/spreadsheets/d/' + encodeURIComponent(savedId) + '/edit#gid=' + studioContext_(type).sheet.getSheetId() : 'https://drive.google.com/drive/folders/' + encodeURIComponent(savedId);
}

function extractSheetId(urlOrId) {
  assertAppAccess_();
  if (!urlOrId) return null;
  const match = String(urlOrId).match(/\/d\/([a-zA-Z0-9-_]+)/);
  return match ? match[1] : String(urlOrId).trim();
}

function extractFolderId(urlOrId) {
  assertAppAccess_();
  if (!urlOrId) return null;
  const match = String(urlOrId).match(/folders\/([a-zA-Z0-9-_]+)/);
  return match ? match[1] : String(urlOrId).trim();
}

function connectStudioSpreadsheet_(type, url) {
  const sheetId = extractSheetId(url);
  if (!sheetId) throw new Error('Enter a spreadsheet URL or ID.');
  SpreadsheetApp.openById(sheetId).getId();
  getCampusProperties_().setProperty(studioKeys_(type).sheet, sheetId);
  return []; // Reload into the new per-user, per-source browser scope.
}

/**
 * Saves the Spreadsheet ID when the user clicks Accept.
 */
function setSpreadsheetUrl(url) {
  assertAppAccess_();
  return connectStudioSpreadsheet_('student', url);
}

function setStaffSpreadsheetUrl(url) {
  assertAppAccess_();
  return connectStudioSpreadsheet_('staff', url);
}

function setCustomSpreadsheetUrl(url) {
  assertAppAccess_();
  return connectStudioSpreadsheet_('custom', url);
}

/**
 * Saves the Photo Folder ID when the user clicks Accept.
 */
function setPhotoFolderUrl(url) {
  assertAppAccess_();
  return connectStudioPhotoFolder_("student", url);
}

/** Saves the staff photo folder after validating access. */
function setStaffPhotoFolderUrl(url) {
  assertAppAccess_();
  return connectStudioPhotoFolder_("staff", url);
}

function setCustomPhotoFolderUrl(url) {
  assertAppAccess_();
  return connectStudioPhotoFolder_("custom", url);
}


// Worksheet selection and explicit column mapping

/** Converts a zero-based column index to an Excel/Google Sheets column letter. */
function spreadsheetColumnLetter_(index) {
  var value = Number(index) + 1;
  var output = '';
  while (value > 0) {
    value -= 1;
    output = String.fromCharCode(65 + value % 26) + output;
    value = Math.floor(value / 26);
  }
  return output;
}

/** Creates position-only column labels. Cell contents and header names are ignored. */
function buildSpreadsheetColumnLabels_(count) {
  return Array.from({
    length: Math.max(0, Number(count) || 0)
  }, function (_, index) {
    return 'Column ' + spreadsheetColumnLetter_(index);
  });
}

/** Returns position-only column labels for the configured studio spreadsheet. */
function getConfiguredSpreadsheetHeaders(type) {
  assertAppAccess_();
  return getStudioSourceInfo(type).headers;
}


// Record validation, identity, and shared CRUD

/** Normalizes IDs for duplicate detection and record lookup. */
function normalizeStudentId_(value) {
  return String(value == null ? '' : value).trim().toLowerCase();
}


// Student record API

/**
 * Stops the studio when the connected spreadsheet already contains the same
 * Student ID on more than one row. Blank IDs are ignored.
 */
function getStudentData() {
  assertAppAccess_();
  return readStudioRecords_("student");
}

function addStudent(record) {
  assertAppAccess_();
  return changeStudioRecord_("student", record, null, false);
}

function updateStudent(record, key) {
  assertAppAccess_();
  return changeStudioRecord_("student", record, key, false);
}

function deleteStudent(key) {
  assertAppAccess_();
  return changeStudioRecord_("student", null, key, true);
}


// Staff record API

function getStaffData() {
  assertAppAccess_();
  return readStudioRecords_("staff");
}

function addStaffMember(record) {
  assertAppAccess_();
  return changeStudioRecord_("staff", record, null, false);
}

function updateStaffMember(record, key) {
  assertAppAccess_();
  return changeStudioRecord_("staff", record, key, false);
}

function deleteStaffMember(key) {
  assertAppAccess_();
  return changeStudioRecord_("staff", null, key, true);
}


// Custom record API

function getCustomData() {
  assertAppAccess_();
  return readStudioRecords_("custom");
}

function addCustomRecord(record) {
  assertAppAccess_();
  return changeStudioRecord_("custom", record, null, false);
}

function updateCustomRecord(record, key) {
  assertAppAccess_();
  return changeStudioRecord_("custom", record, key, false);
}

function deleteCustomRecord(key) {
  assertAppAccess_();
  return changeStudioRecord_("custom", null, key, true);
}


// Shared photo lookup and storage

function studioPhoto_(type, key) {
  const entry = getStudioPhotoManifest(type, [key])[0];
  if (entry.status === 'failed') throw new Error(entry.error);
  return entry.status === 'ready' ? getStudioPhotoFile(type, entry.fileId) : null;
}


// Studio photo API and missing-photo report

function saveStudentPhoto(dataUrl, key) {
  assertAppAccess_();
  const result = saveStudioPhoto_("student", dataUrl, key);
  if (result && result.success) usageRecord_('photo', 'student');
  return result;
}

function getStudentPhoto(key) {
  assertAppAccess_();
  return studioPhoto_('student', key);
}

function getStudentPhotoManifest(keys) {
  assertAppAccess_();
  return getStudioPhotoManifest("student", keys).map(e => {
    if (e.status === "failed") return {
      error: e.error,
      status: "failed"
    };
    return e.status === "ready" ? {
      fileId: e.fileId,
      version: String(e.updated)
    } : null;
  });
}

function getStudentPhotoByFileId(id) {
  assertAppAccess_();
  return getStudioPhotoFile("student", id);
}

function getStudentsMissingPhotos() {
  assertAppAccess_();
  const students = getStudentData();
  const manifest = getStudioPhotoManifest('student', students.map(r => r.recordKey));
  const missing = students.filter((r, i) => manifest[i].status === 'missing');
  const failed = manifest.filter(e => e.status === 'failed');
  if (failed.length) throw new Error('Some photos could not be verified: ' + failed.map(e => e.key + ': ' + e.error).join('; '));
  return {
    totalStudents: students.length,
    missingCount: missing.length,
    missingPhotos: missing.map(r => ({
      idNumber: r.idNumber,
      firstName: r.firstName,
      lastName: r.lastName,
      grade: r.grade
    }))
  };
}

function saveStaffPhoto(dataUrl, key) {
  assertAppAccess_();
  const result = saveStudioPhoto_("staff", dataUrl, key);
  if (result && result.success) usageRecord_('photo', 'staff');
  return result;
}

function getStaffPhoto(key) {
  assertAppAccess_();
  return studioPhoto_('staff', key);
}

function saveCustomPhoto(dataUrl, key) {
  assertAppAccess_();
  const result = saveStudioPhoto_("custom", dataUrl, key);
  if (result && result.success) usageRecord_('photo', 'custom');
  return result;
}

function getCustomPhoto(key) {
  assertAppAccess_();
  return studioPhoto_('custom', key);
}



// Embedded templates are private server helpers, not client-callable endpoints.
function studioEmbeddedTemplate_(name) {
  return HtmlService.createTemplate(studioEmbeddedHtml_(name));
}

function studioEmbeddedHtml_(name) {
  switch (name) {

    case 'ControlCenter':
      return `<!doctype html>
<html>
<head>
  <base target="_top">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Control Center</title>
  <style>
    * {box-sizing:border-box}
    body {margin:0;background:#e9eef5;color:#243247;font:14px 'Segoe UI',Arial,sans-serif}
    main {max-width:1120px;margin:auto;padding:28px}
    header {display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:22px}
    h1 {margin:0;font-size:26px} h2 {font-size:17px;margin:0 0 12px}
    p {line-height:1.5;color:#526277;margin:8px 0}
    a.home,button {display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:38px;padding:8px 13px;border:1px solid #adbdcf;border-radius:6px;background:#f7f9fc;color:#243247;font:600 13px 'Segoe UI',Arial,sans-serif;text-decoration:none;cursor:pointer}
    button.primary {background:#245bc1;color:white;border-color:#245bc1}
    button.danger {color:#b42318;border-color:#d9b0ac;background:#fff5f4}
    button:disabled {opacity:.55;cursor:wait}
    button:focus-visible,a:focus-visible,input:focus-visible {outline:2px solid #245bc1;outline-offset:2px}
    .grid {display:grid;grid-template-columns:1fr 1fr;gap:18px}
    section,details {background:#f9fbfd;border:1px solid #c5d0dd;border-radius:10px;padding:20px;margin-bottom:18px}
    label {display:block;font-size:12px;font-weight:600;margin-bottom:6px}
    input {width:100%;min-height:38px;padding:8px 10px;border:1px solid #adbdcf;border-radius:6px;font:14px 'Segoe UI',Arial,sans-serif;background:white;color:#243247}
    .row {display:flex;gap:8px;align-items:center}.row input {flex:1;min-width:0}
    .small {font-size:12px}.table-top {display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px}.table-top input {max-width:340px}
    .scroll {overflow:auto} table {width:100%;border-collapse:collapse;text-align:left}th,td {padding:11px 9px;border-bottom:1px solid #d5dfe9;vertical-align:middle}th {font-size:12px;color:#526277}td.email {overflow-wrap:anywhere}
    .actions {display:flex;gap:6px;flex-wrap:wrap}.badge {display:inline-block;padding:4px 8px;border-radius:5px;background:#e1eee7;color:#235637;font-size:12px}.badge.disabled {background:#eee5e3;color:#85382b}
    #status {padding:12px 14px;margin-bottom:18px;border-radius:6px;background:#dce7f8;white-space:pre-wrap}#status.error {background:#fce5e2;color:#94271b}
    summary {cursor:pointer;font-weight:600}.transfer-fields {display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:14px 0}
    #csvPreview {max-height:160px;overflow:auto;font-size:12px;padding-left:20px} [hidden] {display:none!important}
    @media(max-width:720px) {main {padding:16px}.grid,.transfer-fields {grid-template-columns:1fr}header,.table-top {align-items:flex-start;flex-direction:column}.row {flex-wrap:wrap}.row button {flex:0 0 auto}}

    /* Studio layout: actions on the left, user list on the right. */
    body {background:linear-gradient(135deg,#f3f5fa,#e9eef5);color:#172033}
    main {max-width:none;width:100%;padding:24px}
    header {background:#f9fbfd;border:1px solid #dce3ec;border-radius:14px;padding:20px 24px}
    .heading {display:flex;align-items:center;gap:16px;min-width:0}
    .studio-icon {display:grid;place-items:center;flex:0 0 58px;height:58px;background:#185adb;border-radius:15px;box-shadow:0 6px 16px #185adb22}
    .studio-icon svg {width:42px;height:42px}
    .eyebrow,.panel-heading {font-size:11px;font-weight:700;letter-spacing:.09em;color:#667085}
    h1 {font-size:28px;margin-top:3px}header p {margin-bottom:0}
    a.home {background:#17243b;color:#fff;border-color:#17243b;white-space:nowrap}
    .workspace {display:grid;grid-template-columns:minmax(300px,350px) minmax(0,1fr);gap:20px;align-items:start}
    .management {min-width:0}.panel-heading {margin:0 0 12px 4px}
    .grid {display:block}.grid section,details {padding:18px;margin-bottom:14px}
    section,details {border-color:#dce3ec;border-radius:12px;box-shadow:0 5px 18px #24324706}
    h2 {display:flex;align-items:center;gap:8px;font-size:17px}
    .management .row {flex-direction:column;align-items:stretch}
    .management .row button {width:100%}
    .transfer-fields {grid-template-columns:1fr}
    .users-panel {min-width:0;min-height:420px;padding:22px}
    .table-top {align-items:flex-start;flex-wrap:wrap}
    .table-top .row {flex:1 1 260px;justify-content:flex-end}
    table {min-width:460px}th {background:#edf2f8;font-weight:700}td {padding-top:14px;padding-bottom:14px}
    button,a.home {min-height:38px;border-radius:8px}
    button.primary {background:#185adb;border-color:#185adb}
    button:hover:not(:disabled) {filter:brightness(.96)}
    #status {font-size:13px;border:1px solid #c9d9f1;border-radius:8px}
    #administrator {overflow-wrap:anywhere}
    #controls > p {margin:0 0 18px;padding:0 4px}
    input[type=file] {font-size:12px;padding:6px}
    input::file-selector-button {border:0;background:#e9eef8;padding:6px;border-radius:4px;color:#243247;margin-right:8px}
    @media(max-width:850px) {.workspace {grid-template-columns:1fr}.users-panel {grid-row:1}.management {grid-row:2}}
    @media(max-width:600px) {main {padding:12px}header {padding:16px}.heading {gap:10px}h1 {font-size:24px}.table-top .row {width:100%;flex-basis:auto}.users-panel {padding:14px}.table-top input {max-width:none}}
    .usage-panel {margin-top:20px;padding:22px}
    #usageSearch {max-width:360px}
    .usage-summary {display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:16px 0}
    .usage-summary > div {background:#edf2f8;padding:14px;border-radius:9px}
    .usage-summary strong {display:block;font-size:24px;color:#185adb}
    .usage-summary span {font-size:12px;color:#526277}
    .usage-table {min-width:900px}
    .usage-table td {font-size:13px;vertical-align:top}
    .usage-table small {display:block;margin-top:4px;color:#667085;font-size:11px}
    .usage-table .breakdown {line-height:1.7;white-space:nowrap}
    @media(max-width:600px) {.usage-panel {padding:14px}.usage-summary {grid-template-columns:1fr}}
  </style>
</head>
<body>
<main>
  <header><div class="heading"><span class="studio-icon"><svg viewBox="0 0 48 48" aria-hidden="true"><path d="M24 4 41 11v12c0 10-7 17-17 22C14 40 7 33 7 23V11Z" fill="#a9c8ff"/><path d="m16 24 6 6 12-13" fill="none" stroke="#185adb" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg></span><div><span class="eyebrow">ADMINISTRATION</span><h1>Control Center</h1><p>Manage access to ID Card Studio.</p></div></div></header>
  <div id="status" role="status" aria-live="polite">Loading access settings…</div>
  <div id="controls" hidden>
    <p class="small">Administrator: <strong id="administrator"></strong></p>
    <div class="workspace"><aside class="management"><div class="panel-heading">Manage Access</div><div class="grid">
      <section>
        <h2><span aria-hidden="true">＋</span> Add User</h2>
        <form id="addForm">
          <label for="newEmail">Google account email</label>
          <div class="row"><input id="newEmail" type="email" autocomplete="off" placeholder="name@school.org" maxlength="254" required><button class="primary" type="submit">＋ Add User</button></div>
        </form>
        <p class="small">New users receive access immediately. This does not send an invitation email.</p>
      </section>
      <section>
        <h2><span aria-hidden="true">⇧</span> Import Users</h2>
        <label for="csvFile">CSV file with an Email column or one email per row</label>
        <input id="csvFile" type="file" accept=".csv,text/csv">
        <p class="small">Up to 500 addresses per import. Existing accounts keep their current status.</p>
        <div id="importPreview" hidden><p id="csvCount"></p><ul id="csvPreview"></ul><button id="importButton" class="primary" type="button">⇧ Import Listed Users</button></div>
      </section>
    </div>
    <details>
      <summary>⚙ Administrator Settings</summary>
      <p>Enter the new administrator's Google account email twice. They must be able to access this deployment under your Google Workspace settings.</p>
      <p class="small">After transfer, you become a regular approved user and lose Control Center access.</p>
      <form id="transferForm">
        <div class="transfer-fields"><div><label for="newAdmin">New administrator email</label><input id="newAdmin" type="email" required maxlength="254"></div><div><label for="confirmAdmin">Confirm new administrator email</label><input id="confirmAdmin" type="email" required maxlength="254"></div></div>
        <button class="danger" type="submit">Transfer Administrator Access</button>
      </form>
    </details>
</aside>
    <section class="users-panel">
      <div class="table-top"><div><h2>Approved Users</h2><p id="userCount" class="small"></p></div><div class="row"><input id="search" type="search" placeholder="Find an email address" aria-label="Find an email address"><button id="refresh" type="button">↻ Refresh</button></div></div>
      <div class="scroll"><table><thead><tr><th>Email Address</th><th>Access</th><th>Actions</th></tr></thead><tbody id="users"></tbody></table></div>
      <p class="small">Disabling or removing access blocks future server requests. It does not delete the user's spreadsheets, photos, or previously downloaded designs.</p>
    </section>

    </div>
    <section class="usage-panel" aria-labelledby="usageHeading">
      <div class="table-top">
        <div><h2 id="usageHeading">▥ Usage Report</h2><p class="small">Activity totals since reporting began or was last cleared. Only administrators can view this report.</p></div>
        <div class="actions"><button id="refreshUsage" type="button">↻ Refresh Report</button><button id="downloadUsage" type="button" disabled>↓ Download CSV</button></div>
      </div>
      <div style="margin-bottom:16px">
        <label for="usageUser">Select a user to clear their usage report</label>
        <div class="row" style="flex-wrap:wrap">
          <select id="usageUser" style="max-width:360px;width:100%;min-height:38px;padding:8px;border:1px solid #adbdcf;border-radius:6px;background:white;color:#243247;font:14px 'Segoe UI',Arial,sans-serif"><option value="">Select User</option></select>
          <button id="clearUsage" class="danger" type="button" disabled>⌫ Clear Selected User’s Report</button>
        </div>
        <p class="small">Clears only the selected user’s history. Their access stays unchanged, and new activity starts fresh totals.</p>
      </div>
      <label for="usageSearch">Find a user</label>
      <input id="usageSearch" type="search" placeholder="Search by email address">
      <p id="usageStatus" class="small" role="status" aria-live="polite">Loading usage report…</p>
      <div class="usage-summary">
        <div><strong id="usageAccounts">0</strong><span>Users with recorded activity</span></div>
        <div><strong id="usagePhotos">0</strong><span>Successful photo saves</span></div>
        <div><strong id="usagePrints">0</strong><span>Print requests</span></div>
      </div>
      <div class="scroll"><table class="usage-table"><thead><tr>
        <th scope="col">User / Access</th><th scope="col">First Visit</th><th scope="col">Latest Activity</th>
        <th scope="col">Studio Openings</th><th scope="col">Photo Saves</th><th scope="col">Print Requests</th>
      </tr></thead><tbody id="usageRows"></tbody></table></div>
      <p class="small">Times use your device’s time zone; CSV timestamps use UTC. Latest activity covers page openings, successful photo saves, and the Print / Save as PDF button. Opening a preview alone is not a print request. Browser-menu printing is not counted, and canceled print dialogs still count as requests.</p>
      <p class="small">Counts are best effort, not an audit log. They do not track time spent or online status. Removed accounts retain their recorded totals. No spreadsheet contents, source links, record names, photos, or card designs are collected.</p>
    </section>

  </div>
</main>
<script>
  let usageReport = null;
  let users = [];
  let pendingImport = [];
  let busy = false;
  let fileSequence = 0;
  const byId = id => document.getElementById(id);
  function call(name, ...args) {
    return new Promise((resolve, reject) => google.script.run.withSuccessHandler(resolve).withFailureHandler(reject)[name](...args));
  }
  function message(text, error) {
    byId('status').textContent = text;
    byId('status').classList.toggle('error', !!error);
  }
  function setBusy(value) {
    busy = value;
    document.querySelectorAll('#controls button, #controls input, #controls select').forEach(node => { node.disabled = value || (node.id === 'downloadUsage' && !usageReport) || (node.id === 'clearUsage' && (!usageReport || !byId('usageUser').value)); });
  }
  async function action(task) {
    if (busy) return;
    setBusy(true);
    try { await task(); }
    catch (error) { message(error.message || String(error), true); }
    finally { setBusy(false); }
  }
  async function refreshUsers() {
    const data = await call('adminListUsers');
    users = data.users;
    byId('administrator').textContent = data.administrator;
    byId('controls').hidden = false;
    byId('userCount').textContent = users.length + ' accounts · ' + users.filter(user => user.enabled).length + ' enabled';
    renderUsers();
  }
  function renderUsers() {
    const host = byId('users');
    host.replaceChildren();
    const query = byId('search').value.trim().toLowerCase();
    const matches = users.filter(user => user.email.includes(query));
    if (!matches.length) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 3;
      cell.textContent = query ? 'No matching accounts.' : 'No users added yet. The administrator already has access.';
      row.appendChild(cell);host.appendChild(row);
    }
    matches.forEach(user => {
      const row = document.createElement('tr');
      const email = document.createElement('td');email.className = 'email';email.textContent = user.email;
      const status = document.createElement('td');
      const badge = document.createElement('span');badge.className = 'badge' + (user.enabled ? '' : ' disabled');badge.textContent = user.enabled ? 'Enabled' : 'Disabled';status.appendChild(badge);
      const controls = document.createElement('td');
      const group = document.createElement('div');group.className = 'actions';
      const toggle = document.createElement('button');toggle.type = 'button';toggle.textContent = user.enabled ? 'Disable' : 'Enable';toggle.disabled = busy;
      toggle.onclick = () => action(async () => {
        await call('adminSetUserAccess', user.email, !user.enabled);
        await refreshUsers();message('Access ' + (user.enabled ? 'disabled' : 'enabled') + ' for ' + user.email + '.');
      });
      const remove = document.createElement('button');remove.type = 'button';remove.className = 'danger';remove.textContent = 'Remove';remove.disabled = busy;
      remove.onclick = () => {
        if (confirm('Remove access for ' + user.email + '? Their records and photos will not be deleted.')) action(async () => {
          await call('adminRemoveUser', user.email);await refreshUsers();message('Removed ' + user.email + '.');
        });
      };
      group.append(toggle, remove);controls.appendChild(group);row.append(email, status, controls);host.appendChild(row);
    });
  }
  function parseEmailCsv(text) {
    const rows = [];let row = [], cell = '', quoted = false, closedQuote = false;
    text = text.replace(/^\\uFEFF/, '');
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (quoted) {
        if (char === '"' && text[i + 1] === '"') { cell += '"'; i++; }
        else if (char === '"') { quoted = false; closedQuote = true; }
        else cell += char;
      } else if (char === '"' && !cell.trim() && !closedQuote) { cell = ''; quoted = true; }
      else if (char === ',' || char === '\\n' || char === '\\r') {
        row.push(cell.trim());cell = '';closedQuote = false;
        if (char !== ',') { if (row.some(Boolean)) rows.push(row);row = [];if (char === '\\r' && text[i + 1] === '\\n') i++; }
      } else {
        if (char === '"' || (closedQuote && char.trim())) throw new Error('The CSV has invalid quotation marks.');
        cell += char;
      }
    }
    if (quoted) throw new Error('The CSV has an unclosed quoted field.');
    row.push(cell.trim());if (row.some(Boolean)) rows.push(row);
    if (!rows.length) throw new Error('The CSV is empty.');
    const header = rows[0].map(value => value.toLowerCase().replace(/[\\s_-]/g, ''));
    let column = header.findIndex(value => ['email', 'emailaddress'].includes(value));
    if (column >= 0) rows.shift();
    else { column = 0;if (rows.some(record => record.length !== 1)) throw new Error('Use an Email column header, or one email address per row.'); }
    const emails = rows.map(record => String(record[column] || '').trim().toLowerCase());
    if (!emails.length || emails.length > 500) throw new Error('Use between 1 and 500 email rows.');
    const invalid = emails.findIndex(email => email.length > 254 || !/^[a-z0-9.!#$%&'*+/=?^_\`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\\.[a-z]{2,}$/i.test(email));
    if (invalid >= 0) throw new Error('Invalid or missing email in data row ' + (invalid + 1) + '.');
    return Array.from(new Set(emails));
  }

  function usageMatches() {
    const query = byId('usageSearch').value.trim().toLowerCase();
    return usageReport ? usageReport.rows.filter(row => row.email.toLowerCase().includes(query)) : [];
  }
  function usageSum(values) {
    return values.reduce((total, count) => total + count, 0);
  }
  function renderUsage() {
    const rows = usageMatches();
    byId('usageAccounts').textContent = rows.filter(row => row.first).length;
    byId('usagePhotos').textContent = rows.reduce((n, row) => n + usageSum(row.photoSaves), 0);
    byId('usagePrints').textContent = rows.reduce((n, row) => n + usageSum(row.printRequests), 0);
    const host = byId('usageRows');
    host.replaceChildren();
    if (!rows.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.textContent = 'No matching users.';
      tr.appendChild(td); host.appendChild(tr);
    }
    rows.forEach(row => {
      const tr = document.createElement('tr');
      function cell(text, detail) {
        const td = document.createElement('td');
        td.textContent = text;
        if (detail) { const small = document.createElement('small'); small.textContent = detail; td.appendChild(small); }
        tr.appendChild(td);
        return td;
      }
      cell(row.email, row.access).className = 'email';
      cell(row.first ? new Date(row.first).toLocaleString() : 'No recorded visit');
      cell(row.last ? new Date(row.last).toLocaleString() : '—');
      [row.openings, row.photoSaves, row.printRequests].forEach(values => {
        const td = cell(String(usageSum(values)));
        const detail = document.createElement('small'); detail.className = 'breakdown';
        values.forEach((count, index) => {
          const line = document.createElement('div');
          line.textContent = ['Student', 'Staff', 'Custom', 'Design'][index] + ': ' + count;
          detail.appendChild(line);
        });
        td.appendChild(detail);
      });
      host.appendChild(tr);
    });
  }
  async function refreshUsageReport() {
    byId('usageStatus').textContent = 'Loading usage report…';
    try {
      usageReport = await call('adminGetUsageReport');
      const select = byId('usageUser');
      const previous = select.value;
      select.replaceChildren(new Option('Select User', ''));
      usageReport.rows.slice().sort((a, b) => a.email.localeCompare(b.email)).forEach(row => {
        select.appendChild(new Option(row.email, row.email));
      });
      if (usageReport.rows.some(row => row.email === previous)) select.value = previous;
      renderUsage();
      byId('usageStatus').textContent = 'Updated ' + new Date(usageReport.generatedAt).toLocaleString() + '. Totals below follow the email search.'
        + (usageReport.unreadable ? ' Some saved counters could not be read.' : '')
        + (usageReport.trackedAccounts >= usageReport.accountLimit ? ' Tracking capacity reached; new accounts may not be recorded.' : '');
    } catch (error) {
      usageReport = null;
      byId('usageRows').replaceChildren();
      ['usageAccounts', 'usagePhotos', 'usagePrints'].forEach(id => { byId(id).textContent = '—'; });
      byId('usageStatus').textContent = 'Unable to load usage report: ' + (error.message || String(error));
    }
    byId('downloadUsage').disabled = !usageReport || busy;
    byId('clearUsage').disabled = !usageReport || busy || !byId('usageUser').value;
  }
  function csvCell(value) {
    let text = String(value == null ? '' : value);
    // Keep email addresses beginning with formula characters as literal CSV text.
    if (/^[=+@\\-\\t\\r]/.test(text)) text = "'" + text;
    return '"' + text.replace(/"/g, '""') + '"';
  }
  function downloadUsage() {
    if (!usageReport) return;
    const header = ['Email', 'Access', 'First Visit (UTC)', 'Latest Activity (UTC)', 'Student Openings', 'Staff Openings', 'Custom Openings', 'Design Openings', 'Student Photo Saves', 'Staff Photo Saves', 'Custom Photo Saves', 'Student Print Requests', 'Staff Print Requests', 'Custom Print Requests'];
    const rows = usageMatches().map(row => [row.email, row.access, row.first || '', row.last || '', ...row.openings, ...row.photoSaves, ...row.printRequests]);
    const csv = [header, ...rows].map(row => row.map(csvCell).join(',')).join('\\r\\n');
    const url = URL.createObjectURL(new Blob(['\\uFEFF' + csv], {type: 'text/csv;charset=utf-8'}));
    const link = document.createElement('a');
    link.href = url; link.download = 'ID-Card-Studio-Usage-' + new Date().toISOString().slice(0, 10) + '.csv';
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  }
  byId('usageSearch').oninput = renderUsage;
  byId('refreshUsage').onclick = () => action(refreshUsageReport);
  byId('downloadUsage').onclick = downloadUsage;
  byId('usageUser').onchange = () => {
    byId('clearUsage').disabled = busy || !usageReport || !byId('usageUser').value;
  };
  byId('clearUsage').onclick = () => {
    const email = byId('usageUser').value;
    if (busy || !usageReport || !email) return;
    if (!confirm('Permanently clear usage history for ' + email + '? Their access and all other users’ reports will stay unchanged. New activity for this user will start fresh totals.')) return;
    action(async () => {
      const result = await call('adminClearUsageReport', email, 'CLEAR_USER_USAGE');
      await refreshUsageReport();
      message(result.cleared ? 'Usage history cleared for ' + email + '. Their access is unchanged.' : 'No recorded usage history to clear for ' + email + '.');
    });
  };

  byId('addForm').onsubmit = event => {
    event.preventDefault();
    action(async () => {
      const result = await call('adminImportUsers', [byId('newEmail').value]);
      byId('newEmail').value = '';await refreshUsers();
      message(result.added ? 'User added with access enabled.' : 'This account is already listed. Its access status was not changed.');
    });
  };
  byId('csvFile').onchange = async event => {
    const sequence = ++fileSequence;
    pendingImport = [];byId('importPreview').hidden = true;
    const file = event.target.files[0];if (!file) return;
    try {
      if (file.size > 262144) throw new Error('Use a CSV smaller than 256 KB.');
      const text = await file.text();if (sequence !== fileSequence) return;
      pendingImport = parseEmailCsv(text);
      byId('csvCount').textContent = pendingImport.length + ' unique email addresses ready to import.';
      byId('csvPreview').replaceChildren();
      pendingImport.forEach(email => { const li = document.createElement('li');li.textContent = email;byId('csvPreview').appendChild(li); });
      byId('importPreview').hidden = false;message('Review the email list, then click Import Listed Users.');
    } catch (error) { if (sequence === fileSequence) message(error.message || String(error), true); }
  };
  byId('importButton').onclick = () => action(async () => {
    const result = await call('adminImportUsers', pendingImport);
    pendingImport = [];byId('csvFile').value = '';byId('importPreview').hidden = true;
    await refreshUsers();message(result.added + ' added; ' + result.unchanged + ' already listed and unchanged.');
  });
  byId('search').oninput = renderUsers;
  byId('refresh').onclick = () => action(async () => { await refreshUsers();message('User list refreshed.'); });
  byId('transferForm').onsubmit = event => {
    event.preventDefault();
    const email = byId('newAdmin').value.trim().toLowerCase();
    const confirmation = byId('confirmAdmin').value.trim().toLowerCase();
    if (email !== confirmation) return message('Both administrator email addresses must match.', true);
    if (!confirm('Transfer administrator access to ' + email + '? You will lose Control Center access.')) return;
    action(async () => {
      await call('adminTransferAccess', email, confirmation);
      if (window.StudioTabsBridge) window.StudioTabsBridge.refreshAccess();
      users = [];pendingImport = [];byId('users').replaceChildren();byId('controls').hidden = true;
      message('Administrator access transferred. You are now a regular approved user. Use the tabs above to continue working.');
    });
  };
  action(async () => { await refreshUsers();message('Manage approved accounts below. View activity totals in the Usage Report.'); await refreshUsageReport(); });
</script>
</body>
</html>
`;

    case 'Custom':
      return `<!DOCTYPE html>
<html>
<head>
<script>
window.STUDIO_URL = <?!= JSON.stringify(webAppUrl) ?>;
window.STUDIO_TYPE = <?!= JSON.stringify(studioType) ?>;
window.STUDIO_SCOPE = <?!= JSON.stringify(clientScope) ?>;
window.STUDIO_STORAGE = {
  getItem: function (k) {
    return localStorage.getItem(STUDIO_SCOPE + k);
  },
  setItem: function (k, v) {
    localStorage.setItem(STUDIO_SCOPE + k, v);
  },
  removeItem: function (k) {
    localStorage.removeItem(STUDIO_SCOPE + k);
  }
};
</script>
<base target="_top">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root {
  --accent:#0f8b8d;
  --ink:#172033;
  --muted:#667085;
  --line:#dce3ec
}
* {
  box-sizing:border-box
}
[hidden] {
  display:none!important
}
body {
  min-height:100vh;
  margin:0;
  padding:24px;
  font-family:"Segoe UI",Arial,sans-serif;
  color:var(--ink);
  background:linear-gradient(135deg,#f4faf9,#edf2f7)
}
input,select,button {
  font:inherit
}
input[type=file] {
  display:none
}
.setup {
  min-height:calc(100vh - 48px);
  display:grid;
  place-items:center
}
.setup-card {
  width:100%;
  max-width:560px;
  padding:30px;
  background:#fff;
  border:1px solid var(--line);
  border-radius:18px;
  box-shadow:0 20px 50px rgba(33,48,73,.13)
}
.mark {
  width:50px;
  height:50px;
  display:grid;
  place-items:center;
  color:#fff;
  background:linear-gradient(135deg,var(--accent),#30b8ad);
  border-radius:14px;
  font-weight:900
}
.mark svg {
  width:35px;
  height:35px;
  display:block;
  filter:drop-shadow(0 2px 3px rgba(23,32,51,.24))
}
h1 {
  margin:14px 0 6px;
  font-size:25px
}
.intro {
  margin:0 0 21px;
  color:var(--muted);
  font-size:14px;
  line-height:1.5
}
.field {
  margin-bottom:14px
}
label {
  display:block;
  margin-bottom:5px;
  font-size:12px;
  font-weight:750
}
.input {
  width:100%;
  min-height:40px;
  padding:8px 11px;
  background:#fff;
  border:1px solid #ccd5e0;
  border-radius:8px;
  outline:none
}
.input:focus {
  border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(15,139,141,.14)
}
.note {
  margin:5px 0 0;
  color:var(--muted);
  font-size:11px
}
.btn {
  min-height:40px;
  padding:9px 13px;
  color:#fff;
  background:var(--accent);
  border:0;
  border-radius:8px;
  font-weight:800;
  cursor:pointer
}
.btn:disabled {
  opacity:.6;
  cursor:wait
}
.btn.gray {
  color:#344054;
  background:#edf0f4
}
.btn.green {
  background:#1f883d
}
.btn.orange {
  background:#e67e22
}
.btn.brown {
  background:#8b4513
}
.full {
  width:100%
}
.pair {
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:9px
}
.status {
  min-height:18px;
  margin:9px 0 0;
  color:#b42318;
  font-size:12px;
  font-weight:700
}
.back {
  display:inline-block;
  margin-top:14px;
  color:var(--accent);
  text-decoration:none;
  font-size:13px;
  font-weight:750
}
.header {
  width:100%;
  max-width:none;
  margin:0 auto 18px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px
}
.brand {
  display:flex;
  align-items:center;
  gap:11px
}
.brand .mark {
  width:44px;
  height:44px
}
.brand h1 {
  margin:0;
  font-size:21px
}
.brand p {
  margin:3px 0 0;
  color:var(--muted);
  font-size:12px
}
.head-actions {
  display:flex;
  gap:8px
}
.pill {
  padding:7px 11px;
  color:#344054;
  background:#fff;
  border:1px solid var(--line);
  border-radius:999px;
  text-decoration:none;
  font-size:12px;
  font-weight:750;
  cursor:pointer
}
.pill.id-studio-link {
  display:inline-flex;
  align-items:center;
  color:#fff;
  background:#17233a;
  border-color:#17233a;
  border-radius:9px
}
.pill.id-studio-link:hover {
  color:#fff;
  background:#101a2c;
  border-color:#101a2c
}
.workspace {
  width:100%;
  max-width:none;
  min-height:calc(100vh - 110px);
  margin:auto;
  display:grid;
  grid-template-columns:350px 1fr;
  gap:18px
}
.panel {
  background:#fff;
  border:1px solid var(--line);
  border-radius:14px;
  box-shadow:0 10px 30px rgba(33,48,73,.08)
}
.controls {
  height:max-content;
  display:flex;
  flex-direction:column;
  overflow:hidden
}
.section {
  padding:15px 16px;
  border-bottom:1px solid #edf0f4
}
.section:last-child {
  border-bottom:0
}
.section-title {
  margin:0 0 11px;
  color:#475467;
  font-size:11px;
  font-weight:800;
  letter-spacing:.08em;
  text-transform:uppercase
}
.data-sources-panel {
  order:99;
  border-top:1px solid #edf0f4;
  border-bottom:0
}
.data-sources-panel>summary {
  margin:0;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:10px;
  list-style:none;
  cursor:pointer;
  user-select:none
}
.data-sources-panel>summary::-webkit-details-marker {
  display:none
}
.data-sources-panel>summary::after {
  content:'+';
  width:23px;
  height:23px;
  display:grid;
  place-items:center;
  flex:0 0 23px;
  color:var(--accent);
  background:#e8f7f7;
  border-radius:6px;
  font-size:17px;
  line-height:1
}
.data-sources-panel[open]>summary {
  margin-bottom:11px
}
.data-sources-panel[open]>summary::after {
  content:'−'
}
.source-sheet-button {
  background:#185adb!important
}
.source-sheet-button:hover {
  background:#1248b5!important
}
.source-folder-button {
  background:#0f8b8d!important
}
.source-folder-button:hover {
  background:#0b7173!important
}
.source-design-button {
  background:#7141c6!important
}
.source-design-button:hover {
  background:#58309f!important
}
.stack {
  display:flex;
  flex-direction:column;
  gap:9px
}
.source-row {
  display:flex;
  align-items:center;
  gap:8px
}
.source-row .input {
  min-width:0;
  flex:1
}
.source-row .btn {
  width:auto;
  flex:0 0 auto
}
.search {
  display:flex;
  gap:8px
}
.search .input {
  min-width:0
}
.grid {
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:9px
}
.grid .btn.wide {
  grid-column:1/-1
}
.preview {
  overflow:hidden
}
.preview-head {
  padding:14px 18px;
  border-bottom:1px solid var(--line)
}
.preview-head h2 {
  margin:0;
  font-size:16px
}
.preview-head p {
  margin:3px 0 0;
  color:var(--muted);
  font-size:12px
}
.canvas {
  min-height:calc(100vh - 174px);
  padding:35px;
  display:grid;
  place-items:start center;
  background-color:#e5f0f0;
  background-image:radial-gradient(rgba(15,139,141,.14) 1px,transparent 1px);
  background-size:18px 18px
}
.controls .input,.controls .btn {
  min-height:38px
}
.id-card {
  width:204px;
  height:324px;
  padding:8px;
  display:flex;
  flex-direction:column;
  align-items:center;
  overflow:hidden;
  background:#fff;
  border:3px solid var(--accent);
  border-radius:12px;
  box-shadow:0 12px 26px rgba(23,32,51,.17)
}
.card-head {
  width:100%;
  height:74px;
  padding-top:17px;
  position:relative;
  display:grid;
  place-items:center;
  border-bottom:2px solid var(--accent)
}
.slot {
  width:56px;
  height:12px;
  position:absolute;
  top:1px;
  left:50%;
  transform:translateX(-50%);
  border:1px dashed #98a2b3;
  border-radius:8px
}
.logo {
  width:100%;
  height:100%;
  max-width:184px;
  max-height:56px;
  object-fit:contain
}
.photo-frame {
  width:112px;
  height:136px;
  margin:7px 0 6px;
  display:grid;
  place-items:center;
  overflow:hidden;
  color:var(--muted);
  background:#f2f4f7;
  border:1px dashed var(--accent);
  border-radius:10px;
  font-size:9px;
  font-weight:750
}
.photo {
  width:100%;
  height:100%;
  object-fit:cover
}
.details {
  width:100%;
  text-align:center
}
.first,.last {
  overflow:hidden;
  font-size:16px;
  font-weight:900;
  line-height:1.02;
  text-overflow:ellipsis;
  text-transform:uppercase;
  white-space:nowrap
}
.role {
  margin-top:5px;
  color:var(--accent);
  font-size:12px;
  font-weight:850;
  text-transform:uppercase
}
.number {
  margin-top:4px;
  color:#475467;
  font-size:10px;
  font-weight:750
}
.modal {
  position:fixed;
  inset:0;
  z-index:1000;
  padding:18px;
  display:grid;
  place-items:center;
  background:rgba(15,23,42,.66)
}
.modal-card {
  width:100%;
  max-width:440px;
  max-height:calc(100vh - 36px);
  padding:22px;
  position:relative;
  overflow:auto;
  background:#fff;
  border-radius:14px
}
.modal-card h2 {
  margin:0 42px 17px 0
}
.modal-close {
  width:34px;
  height:34px;
  position:absolute;
  top:14px;
  right:14px;
  display:grid;
  place-items:center;
  color:#475467;
  background:#f2f4f7;
  border:1px solid #d0d5dd;
  border-radius:50%;
  font-size:22px;
  font-weight:800;
  line-height:1;
  cursor:pointer
}
.modal-close:hover {
  color:#b42318;
  background:#fff1f0;
  border-color:#f1a7a2
}
.modal-actions {
  display:flex;
  gap:9px;
  margin-top:15px
}
.modal-actions .btn {
  flex:1
}
#saveButton {
  order:1
}
#deleteRecordButton {
  order:2
}
#addModal .modal-actions .gray {
  order:3
}
#cardMount.previewing-all {
  width:100%
}
.all-card-preview-grid {
  width:100%;
  display:flex;
  flex-wrap:wrap;
  align-items:flex-start;
  justify-content:center;
  gap:24px
}
.all-card-preview-status {
  width:100%;
  margin:0 0 18px;
  color:#475467;
  font-size:12px;
  font-weight:750;
  text-align:center
}
@media(max-width:760px) {
  body {
    padding:14px
  }
  .workspace {
    grid-template-columns:1fr;
    min-height:0
  }
  .canvas {
    min-height:410px;
    padding:28px 12px
  }
  .brand p {
    display:none
  }
}
@media print {
  @page {
    size:auto;
    margin:0
  }
  body {
    padding:0!important;
    margin:0!important;
    background:transparent!important;
    -webkit-print-color-adjust:exact!important;
    print-color-adjust:exact!important
  }
  .header,.controls,.preview-head,.modal,.all-card-preview-status {
    display:none!important
  }
  .workspace,.preview,.canvas {
    width:auto!important;
    min-height:0!important;
    padding:0!important;
    margin:0!important;
    display:block!important;
    background:transparent!important;
    border:0!important;
    box-shadow:none!important
  }
  .id-card {
    width:53.98mm!important;
    height:85.60mm!important;
    padding:.083in!important;
    border-radius:0!important;
    box-shadow:none!important
  }
  .slot {
    border-color:transparent!important
  }
}

/* Match the compact Staff name-search row without changing other inputs. */
.custom-name-search {
  display:flex;
  align-items:stretch;
  gap:8px;
}
.custom-name-search #customRecordSearchInput {
  flex:1 1 0;
  width:0;
  min-width:0;
  height:38px;
  min-height:38px;
  padding:8px 11px;
  box-sizing:border-box;
}
.custom-name-search .btn {
  flex:0 0 auto;
  width:auto;
  height:38px;
  min-height:38px;
  padding:8px 12px;
  white-space:nowrap;
  box-sizing:border-box;
}

/* Match Student Studio's compact name search. */
.name-search-wrapper {position:relative;width:100%;display:flex;align-items:center;}
.name-search-wrapper .name-search-input {width:100%;min-width:0;height:38px;min-height:38px;padding:8px 38px 8px 11px;font:13px "Segoe UI",Arial,sans-serif;border:1px solid #d0d7de;border-radius:8px;background:#fff;outline:none;box-sizing:border-box;}
.name-search-wrapper .name-search-input:focus {border-color:#0969da;box-shadow:0 0 0 2px rgba(9,105,218,.2);}
.name-search-wrapper .search-btn {position:absolute;right:4px;top:50%;transform:translateY(-50%);width:30px;height:30px;min-height:30px;padding:4px;display:flex;align-items:center;justify-content:center;color:#57606a;background:none;border:none;border-radius:4px;cursor:pointer;}
.name-search-wrapper .search-btn:hover {color:#0969da;background:#f3f4f6;}
.name-search-wrapper .search-btn:focus-visible {outline:2px solid #0969da;outline-offset:1px;}
.name-search-wrapper .search-btn::before {display:none!important;}
</style>
</head>
<body>
<header id="header" class="header">
<div class="brand">
<div class="mark" role="img" aria-label="Custom ID card">
<svg viewBox="0 0 48 48" aria-hidden="true">
<rect x="5" y="9" width="38" height="30" rx="6" fill="#fff"/>
<circle cx="16" cy="23" r="6" fill="#9f7aea"/>
<path d="M9 35c1-5.5 3.5-8 7-8s6 2.5 7 8" fill="#ff8a65"/>
<rect x="26" y="17" width="11" height="3" rx="1.5" fill="#2563eb"/>
<rect x="26" y="23" width="9" height="3" rx="1.5" fill="#22b8a7"/>
<circle cx="37" cy="34" r="7" fill="#ffd34e"/>
<path d="M37 30v8M33 34h8" stroke="#7b4f00" stroke-width="2.5" stroke-linecap="round"/>
</svg>
</div>
<div>
<h1>Custom ID Card Studio</h1>
<p>Search custom records, manage their photos, and print cards using your selected design.</p>
</div>
</div>
<div class="head-actions">
<a class="pill id-studio-link" href="<?!= webAppUrl ?>" target="_top">← ID Card Studio</a>
</div>
</header>
<main id="workspace" class="workspace">
<aside class="panel controls">
<details id="customDataSources" class="section data-sources-panel">
<summary class="section-title">Data Sources</summary>
<p class="note">Connect a spreadsheet to open Design Mapping. Choose a design, worksheet, header option, and columns together. Internal record and photo columns are reused when you change designs.</p>
<div class="field">
<label for="sheetUrl">Custom Spreadsheet</label>
<div class="source-row">
<input id="sheetUrl" class="input" placeholder="Paste Google Spreadsheet URL or ID">
<button id="connectCustomSheetButton" class="btn source-sheet-button" onclick="connectCustomSpreadsheet()">Connect</button>
</div>
<p id="sheetNote" class="note">No Custom spreadsheet connected yet.</p>
</div>
<div class="field">
<label for="folderUrl">Custom Photo Folder</label>
<div class="source-row">
<input id="folderUrl" class="input" placeholder="Paste Google Drive folder URL or ID">
<button id="connectCustomFolderButton" class="btn source-folder-button" onclick="connectCustomPhotoFolder()">Connect</button>
</div>
<p id="folderNote" class="note">Photo filenames must match the record full name, for example Alex Smith.jpg.</p>
</div>
<div class="field">
<label>Custom Card Design</label>
<input id="customDesignFile" type="file" accept=".json,application/json" onchange="selectCustomCardDesign(event)">
<button id="customDesignButton" class="btn full source-design-button" onclick="openCustomColumnMapping()" title="Choose a saved Design Studio .json file from your device.">Select Card Design</button>
<p id="customDesignNote" class="note">Choose a .json design file saved in Design Studio, then map its data elements below.</p>
</div>
<div class="field">
<label>Design Mapping</label>
<button id="customMappingButton" class="btn full" style="background:#d97706" type="button" onclick="openCustomColumnMapping()" title="Choose which spreadsheet column supplies each data element in this design.">Design Mapping</button>
<p id="customMappingNote" class="note">Connect a spreadsheet, select a design, then match its data elements to spreadsheet columns.</p>
</div>
<p id="setupStatus" class="status">
</p>
</details>
<section class="section">
<h2 class="section-title">Find Records</h2>
<div class="stack">
<div class="name-search-wrapper">
<input id="customRecordSearchInput" class="name-search-input" type="search" placeholder="Search by Custom Record" aria-label="Search by Custom Record" autocomplete="off" onkeydown="if(event.key==='Enter'){event.preventDefault();searchCustomRecord()}">
<button class="search-btn" type="button" onclick="searchCustomRecord()" title="Search by Custom Record" aria-label="Search by Custom Record">
<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
</button>
</div>
<select id="recordSelect" class="input" onchange="selectRecord(this.value)">
<option value="">Select Record</option>
</select>
</div>
</section>
<section class="section">
<h2 class="section-title">Actions</h2>
<div class="grid">
<button class="btn" style="background:#1f883d" onclick="openAdd()" title="Add a custom record using the fields mapped in your selected design.">Add Record</button>
<button class="btn" style="background:#7141c6" onclick="openEdit()" title="Change or delete the selected custom record.">Edit Record</button>
<button class="btn wide" style="background:#d97706" onclick="openCamera()" title="Open the camera for the selected record. Capture, review, and save a photo.">Take Photo</button>
</div>
<p id="actionStatus" class="status">
</p>
</section>
<section class="section">
<h2 class="section-title">Data</h2>
<div class="grid">
<button class="btn" style="background:#185adb" onclick="openSavedResource('spreadsheet')" title="Open the connected spreadsheet in a new tab. Return here to reload saved changes.">Open the Spreadsheet</button>
<button class="btn" style="background:#0f8b8d" onclick="openSavedResource('folder')" title="Open the connected Google Drive photo folder in a new tab.">Open the Photo Folder</button>
</div>
</section>
</aside>
<section class="panel preview">
<div class="preview-head" style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
<div>
<h2>Custom ID Card Preview</h2>
<p>Search by a name or mapped field to preview all matches, select one record, or preview all custom cards. Print displayed cards or all cards, then choose Front Side, Back Side, or both in print preview.</p>
</div>
<div style="display:flex;align-items:center;justify-content:flex-end;gap:9px;flex-wrap:wrap">
<button id="previewAllCustomButton" class="btn" style="background:#7141c6" type="button" onclick="previewAllCustomCards()" title="Display all records using the selected design. This does not print.">Preview All Custom ID Cards</button>
<button id="printSelectedCustomButton" class="btn" style="background:#b42318" type="button" onclick="CardDesignRuntime.printCards(document.getElementById('cardMount'),{title:'Selected Custom ID Card'})" title="Print the displayed search results or selected record and choose the card side.">Print Displayed Custom ID Cards</button>
<button id="printAllCustomButton" class="btn" style="background:#185adb" type="button" onclick="printAllCustomCards()" title="Prepare all records for printing, then choose the card side in print preview.">Print All Custom ID Cards</button>
</div>
</div>
<div class="canvas">
<div id="cardMount">
</div>
</div>
</section>
</main>
<div id="addModal" class="modal" role="dialog" aria-modal="true" aria-hidden="true" aria-labelledby="recordModalTitle" onclick="if(event.target===this) closeAdd()" hidden>
<form class="modal-card" onsubmit="saveRecord(event)">
<button type="button" class="modal-close" aria-label="Close record window" title="Close" onclick="closeAdd()">×</button>
<h2 id="recordModalTitle">Add Custom Record</h2>
<p class="note">These fields come from the mapped data elements on both sides of your selected design. Save writes the values to the connected custom spreadsheet.</p>
<div id="customDesignLinkedFields">
</div>
<div class="modal-actions">
<button id="saveButton" class="btn green" type="submit" title="Save the entered values to the connected spreadsheet.">Save</button>
<button id="deleteRecordButton" type="button" class="btn" style="background:#b42318" onclick="deleteCurrentRecord()" hidden title="Delete this spreadsheet record and move matching photos to Drive Trash.">Delete</button>
<button type="button" class="btn gray" onclick="closeAdd()" title="Close without saving these changes.">Cancel</button>
</div>
<p id="addStatus" class="status">
</p>
</form>
</div>
<?!= include('DesignRuntime'); ?>
<script>
const LOGO_KEY = 'custom_card_logo';
const ACTIVE_DESIGN_KEY = 'active_custom_card_design';
let configuration = {
  hasSpreadsheet: false,
  hasPhotoFolder: false
};
let records = [];
let customSpreadsheetHeaders = [];
let activeId = '';
let logoData = '';
let activeCustomDesign = null;
let customColumnMap = {};
let editingCustomId = '';
let customCameraWindow = null;
let cameraTargetIndex = '';
let cameraTargetName = '';
let customPreviewRequest = 0;
window.addEventListener('DOMContentLoaded', function () {
  closeAdd();
  logoData = STUDIO_STORAGE.getItem(LOGO_KEY) || '';
  activeCustomDesign = loadCustomDesign();
  syncCustomColumnMapping();
  google.script.run.withSuccessHandler(function (result) {
    configuration = result || configuration;
    updateSetup();
    if (configuration.hasSpreadsheet) google.script.run.withSuccessHandler(populate).withFailureHandler(showError).getCustomData();else populate([]);
  }).withFailureHandler(showError).getCustomConfiguration();
});
window.addEventListener('pageshow', function () {
  closeAdd();
});
document.addEventListener('keydown', function (event) {
  if (event.key === 'Escape' && !document.getElementById('addModal').hidden) closeAdd();
});
function updateSetup() {
  const sheetButton = document.getElementById('connectCustomSheetButton');
  const folderButton = document.getElementById('connectCustomFolderButton');
  if (configuration.hasSpreadsheet) {
    document.getElementById('sheetUrl').placeholder = 'Paste another URL or ID to change it';
    document.getElementById('sheetNote').textContent = 'Custom spreadsheet connected. Saved changes reload when you return to this studio.';
    document.getElementById('sheetNote').style.color = '#1f883d';
    sheetButton.textContent = 'Change';
  } else {
    document.getElementById('sheetNote').textContent = 'No Custom spreadsheet connected yet.';
    document.getElementById('sheetNote').style.color = '#b42318';
    sheetButton.textContent = 'Connect';
  }
  if (configuration.hasPhotoFolder) {
    document.getElementById('folderUrl').placeholder = 'Paste another URL or ID to change it';
    document.getElementById('folderNote').textContent = 'Custom photo folder connected. Photos keep friendly full-name filenames and are linked to stable internal records.';
    document.getElementById('folderNote').style.color = '#1f883d';
    folderButton.textContent = 'Change';
  } else {
    document.getElementById('folderNote').textContent = 'No Custom photo folder connected yet.';
    document.getElementById('folderNote').style.color = '#b42318';
    folderButton.textContent = 'Connect';
  }
  if (activeCustomDesign) {
    document.getElementById('customDesignButton').textContent = 'Selected: ' + (activeCustomDesign.selectedFileName || activeCustomDesign.name);
    document.getElementById('customDesignNote').textContent = 'Select this button to choose a different .json design file. Review its column mapping before use.';
    document.getElementById('customDesignNote').style.color = '#1f883d';
  } else {
    document.getElementById('customDesignButton').textContent = 'Select Card Design';
    document.getElementById('customDesignNote').textContent = 'Choose a .json design file saved in Design Studio, then map its data elements below.';
    document.getElementById('customDesignNote').style.color = '#667085';
  }
  if (!configuration.hasSpreadsheet || !configuration.hasPhotoFolder || !activeCustomDesign) document.getElementById('customDataSources').open = true;
  updateCustomMappingState();
}
function normalizeSelectedCardDesign(design, fileName) {
  if (!design || design.fileType !== 'ID_CARD_DESIGN' || !Array.isArray(design.elements) && !Array.isArray(design.frontElements) && !Array.isArray(design.backElements)) return null;
  design.frontElements = Array.isArray(design.frontElements) ? design.frontElements : Array.isArray(design.elements) ? design.elements : [];
  design.backElements = Array.isArray(design.backElements) ? design.backElements : [];
  design.elements = design.frontElements;
  design.dataSource = 'custom';
  if (fileName && fileName !== 'ID Card Design') design.selectedFileName = fileName;
  if (!String(design.name || '').trim()) design.name = String(fileName || '').replace(/\\.json$/i, '') || 'ID Card Design';
  return design;
}
function loadCustomDesign() {
  try {
    return normalizeSelectedCardDesign(JSON.parse(STUDIO_STORAGE.getItem(ACTIVE_DESIGN_KEY) || 'null'), 'ID Card Design');
  } catch (error) {
    return null;
  }
}
function syncCustomColumnMapping() {
  customColumnMap = activeCustomDesign ? CardDesignRuntime.loadColumnMapping(activeCustomDesign, 'custom') : {};
  if (activeCustomDesign) CardDesignRuntime.applyColumnMapping(activeCustomDesign, customColumnMap);
  updateCustomMappingState();
}
function updateCustomMappingState() {
  const button = document.getElementById('customMappingButton');
  const note = document.getElementById('customMappingNote');
  if (!button || !note) return;
  button.disabled = false;
  button.textContent = 'Design Mapping';
  note.textContent = 'Select a design, worksheet, header option, and columns together.';
}

function openCustomColumnMapping(onlyIfNeeded) {
  StudioReliability.openDesignMapping({
    design: activeCustomDesign
  });
}
function customMappedValue(record, type, fallbackValue) {
  if (activeCustomDesign && record) {
    const value = CardDesignRuntime.getLinkedValue(activeCustomDesign, record, type);
    if (String(value || '').trim()) return String(value).trim();
  }
  return String(fallbackValue == null ? '' : fallbackValue).trim();
}
function customDropdownName(record) {
  record = record || {};
  const first = customMappedValue(record, 'firstName', record.firstName);
  const middle = customMappedValue(record, 'middleName', record.middleName);
  const last = customMappedValue(record, 'lastName', record.lastName);
  const full = customMappedValue(record, 'fullName', record.fullName);
  const parts = [first, middle, last].filter(Boolean).join(' ');
  return first && last ? parts : full || parts || 'Unnamed Record';
}
function customMappedFullName(record) {
  record = record || {};
  const firstName = customMappedValue(record, 'firstName', record.firstName);
  const lastName = customMappedValue(record, 'lastName', record.lastName);
  const fullName = customMappedValue(record, 'fullName', record.fullName);
  if (firstName && lastName) return firstName + ' ' + lastName;
  return fullName || firstName || lastName || 'Unnamed Record';
}
function selectCustomCardDesign(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function (loadEvent) {
    try {
      const design = normalizeSelectedCardDesign(JSON.parse(loadEvent.target.result), file.name);
      if (!design) throw new Error('Choose a .json design file saved by Design Studio.');
      activeCustomDesign = design;
      STUDIO_STORAGE.setItem(ACTIVE_DESIGN_KEY, JSON.stringify(design));
      syncCustomColumnMapping();
      updateSetup();
      document.getElementById('setupStatus').textContent = '';
      const index = document.getElementById('recordSelect').value;
      if (index !== '' && records[index]) renderCard(records[index]);else renderEmptyCustomCard();
      openCustomColumnMapping(true);
    } catch (error) {
      showError(error);
    }
  };
  reader.readAsText(file);
  event.target.value = '';
}
function showError(error) {
  const status = document.getElementById('setupStatus');
  status.style.color = '#b42318';
  status.textContent = error && error.message ? error.message : String(error);
}
function connectCustomSpreadsheet() {
  const input = document.getElementById('sheetUrl');
  const url = input.value.trim();
  if (!url) {
    alert('Enter a spreadsheet URL or ID first.');
    return;
  }
  StudioReliability.openDesignMapping({
    spreadsheetUrl: url,
    design: activeCustomDesign
  });
}
function connectCustomPhotoFolder() {
  const input = document.getElementById('folderUrl');
  const url = input.value.trim();
  const button = document.getElementById('connectCustomFolderButton');
  const status = document.getElementById('setupStatus');
  if (!url) return showError('Please paste the Custom Photo Folder URL or ID.');
  button.disabled = true;
  status.style.color = '#667085';
  status.textContent = 'Connecting Custom photo folder...';
  google.script.run.withSuccessHandler(function (result) {
    StudioReliability.carryDesignToScope(result && result.scope);
    button.disabled = false;
    input.value = '';
    configuration.hasPhotoFolder = true;
    updateSetup();
    status.style.color = '#1f883d';
    status.textContent = 'Custom photo folder connected successfully.';
    StudioReliability.reopen();
  }).withFailureHandler(function (error) {
    button.disabled = false;
    showError('Photo folder not changed: ' + (error.message || String(error)));
  }).setCustomPhotoFolderUrl(url);
}
function openSavedResource(resourceType) {
  const newTab = window.open('about:blank', '_blank');
  if (!newTab) {
    alert('Allow pop-ups for this app, then open the spreadsheet or photo folder again.');
    return;
  }
  google.script.run.withSuccessHandler(function (url) {
    newTab.location.href = url;
  }).withFailureHandler(function (error) {
    newTab.close();
    alert(error.message || String(error));
  }).getConfiguredResourceUrl('custom', resourceType);
}
function populate(data, preferredRecordKey) {
  records = data || [];
  updateCustomMappingState();
  if (records.length && Array.isArray(records[0]._headers)) customSpreadsheetHeaders = records[0]._headers.slice();else if (configuration.hasSpreadsheet) google.script.run.withSuccessHandler(function (headers) {
    customSpreadsheetHeaders = Array.isArray(headers) ? headers : [];
    updateCustomMappingState();
  }).withFailureHandler(function () {
    customSpreadsheetHeaders = [];
  }).getConfiguredSpreadsheetHeaders('custom');
  const select = document.getElementById('recordSelect');
  select.innerHTML = '<option value="">Select Record</option>';
  records.forEach(function (record, index) {
    const option = document.createElement('option');
    const displayName = customDropdownName(record);
    const displayTitle = customMappedValue(record, 'title', record.title) || customMappedValue(record, 'department', record.department);
    option.value = String(index);
    option.textContent = displayName + (displayTitle ? ' (' + displayTitle + ')' : '');
    select.appendChild(option);
  });
  const requestedKey = String(preferredRecordKey || '');
  if (records.length && requestedKey) {
    const preferredIndex = records.findIndex(function (record) {
      return String(record.recordKey || '') === requestedKey;
    });
    if (preferredIndex !== -1) {
      select.value = String(preferredIndex);
      selectRecord(String(preferredIndex));
      return;
    }
  }
  select.value = '';
  activeId = '';
  renderEmptyCustomCard();
}
function selectRecord(index) {
  window.activeNameSearch = '';
  if (index === '' || !records[index]) {
    activeId = '';
    renderEmptyCustomCard();
    return;
  }
  activeId = String(records[index].recordKey || '');
  renderCard(records[index]);
}
function searchCustomRecord() {
  const input = document.getElementById('customRecordSearchInput');
  const query = input.value.trim();
  if (!query) return;
  const matches = CardDesignRuntime.matchingRecords(activeCustomDesign, records, query, true);
  if (!matches.length) {
    alert('No matching records were found for: ' + query);
    return;
  }
  const select = document.getElementById('recordSelect');
  select.value = '';
  activeId = '';
  if (matches.length === 1) {
    select.value = String(records.indexOf(matches[0]));
    selectRecord(select.value);
  } else previewAllCustomCards(matches);
  window.activeNameSearch = query;
  input.value = '';
}
function renderEmptyCustomCard() {
  const mount = document.getElementById('cardMount');
  customPreviewRequest += 1;
  setCustomPreviewMode(false);
  mount.innerHTML = '';
  if (!activeCustomDesign) return;
  CardDesignRuntime.render(mount, activeCustomDesign, {}, {
    recordId: '',
    logoData: activeCustomDesign.logoData || logoData,
    photoLoading: false,
    emptyPreview: true
  });
}
function escapeHtml(value) {
  return String(value == null ? '' : value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}
function getCustomRecordsForReliability() {
  return records;
}
function renderCard(record) {
  const mount = document.getElementById('cardMount');
  const token = ++customPreviewRequest;
  setCustomPreviewMode(false);
  if (!activeCustomDesign) return;
  const key = CardDesignRuntime.getPhotoKey(activeCustomDesign, record);
  const options = {
    recordId: record.recordKey,
    photoLoading: !!key
  };
  CardDesignRuntime.render(mount, activeCustomDesign, record, options);
  if (key) StudioReliability.photo('custom', key).then(data => {
    if (token !== customPreviewRequest) return;
    options.photoData = data;
    options.photoLoading = false;
    CardDesignRuntime.render(mount, activeCustomDesign, record, options);
  }).catch(() => {
    if (token !== customPreviewRequest) return;
    options.photoLoading = false;
    options.photoError = true;
    CardDesignRuntime.render(mount, activeCustomDesign, record, options);
  });
}
function loadCustomPhotoForPrint(record) {
  const key = CardDesignRuntime.getPhotoKey(activeCustomDesign, record);
  return key ? StudioReliability.photo('custom', key).catch(() => '') : Promise.resolve('');
}
function setCustomPreviewMode(showingAll) {
  const mount = document.getElementById('cardMount');
  const selectedPrintButton = document.getElementById('printSelectedCustomButton');
  if (mount) mount.classList.toggle('previewing-all', Boolean(showingAll));
  if (selectedPrintButton) selectedPrintButton.disabled = false;
}
async function previewAllCustomCards(subset) {
  window.activeNameSearch = '';
  const previewRecords = Array.isArray(subset) ? subset : records;
  if (!Array.isArray(subset)) window.activeNameSearch = '';
  document.getElementById('recordSelect').value = '';
  activeId = '';
  if (!activeCustomDesign) {
    alert('Please select a Custom card design first.');
    return;
  }
  if (!previewRecords.length) {
    alert('There are no Custom records to preview.');
    return;
  }
  const requestToken = ++customPreviewRequest;
  const button = document.getElementById('previewAllCustomButton');
  const mount = document.getElementById('cardMount');
  const status = document.createElement('p');
  const grid = document.createElement('div');
  status.className = 'all-card-preview-status';
  status.textContent = 'Loading photos for 0 of ' + previewRecords.length + ' Custom cards…';
  grid.className = 'all-card-preview-grid';
  mount.innerHTML = '';
  setCustomPreviewMode(true);
  mount.append(status, grid);
  const jobs = previewRecords.map(function (record) {
    const cardMount = document.createElement('div');
    const photoLookupKey = CardDesignRuntime.getPhotoKey(activeCustomDesign, record);
    const options = {
      recordId: String(record.recordKey || ''),
      logoData: activeCustomDesign.logoData || logoData,
      photoLoading: Boolean(photoLookupKey)
    };
    grid.appendChild(cardMount);
    CardDesignRuntime.render(cardMount, activeCustomDesign, record, options);
    return {
      record: record,
      mount: cardMount,
      options: options
    };
  });
  let nextJob = 0;
  let completedJobs = 0;
  const workerCount = Math.min(6, jobs.length);
  async function worker() {
    while (nextJob < jobs.length && requestToken === customPreviewRequest) {
      const job = jobs[nextJob];
      nextJob += 1;
      job.options.photoData = await loadCustomPhotoForPrint(job.record);
      if (requestToken !== customPreviewRequest) return;
      job.options.photoLoading = false;
      CardDesignRuntime.render(job.mount, activeCustomDesign, job.record, job.options);
      completedJobs += 1;
      status.textContent = 'Loading photos for ' + completedJobs + ' of ' + jobs.length + ' Custom cards…';
    }
  }
  button.disabled = true;
  try {
    await Promise.all(Array.from({
      length: workerCount
    }, function () {
      return worker();
    }));
    if (requestToken === customPreviewRequest) status.textContent = 'Showing ' + jobs.length + ' Custom ID cards.';
  } finally {
    button.disabled = false;
  }
}
async function printAllCustomCards() {
  if (!activeCustomDesign) {
    alert('Please select a Custom card design first.');
    return;
  }
  if (!records.length) {
    alert('There are no Custom records to print.');
    return;
  }
  const printWindow = CardDesignRuntime.createPrintWindow('Loading photos for ' + records.length + ' Custom cards…');
  if (!printWindow) return;
  const button = document.getElementById('printAllCustomButton');
  const batchContainer = document.createElement('div');
  const jobs = records.map(function (record) {
    const mount = document.createElement('div');
    const options = {
      recordId: String(record.recordKey || ''),
      logoData: activeCustomDesign.logoData || logoData,
      photoLoading: true
    };
    batchContainer.appendChild(mount);
    CardDesignRuntime.render(mount, activeCustomDesign, record, options);
    return {
      record: record,
      mount: mount,
      options: options
    };
  });
  let nextJob = 0;
  let completedJobs = 0;
  const workerCount = Math.min(6, jobs.length);
  async function worker() {
    while (nextJob < jobs.length && !printWindow.closed) {
      const job = jobs[nextJob];
      nextJob += 1;
      job.options.photoData = await loadCustomPhotoForPrint(job.record);
      job.options.photoLoading = false;
      CardDesignRuntime.render(job.mount, activeCustomDesign, job.record, job.options);
      completedJobs += 1;
      if (!printWindow.closed) {
        const status = printWindow.document.getElementById('printPreparationStatus');
        if (status) status.textContent = 'Loaded ' + completedJobs + ' of ' + jobs.length + ' Custom cards…';
      }
    }
  }
  button.disabled = true;
  try {
    await Promise.all(Array.from({
      length: workerCount
    }, function () {
      return worker();
    }));
    if (!printWindow.closed) CardDesignRuntime.printCards(batchContainer, {
      printWindow: printWindow,
      title: 'All Custom ID Cards'
    });
  } finally {
    button.disabled = false;
  }
}

function renderCustomDesignFields(record) {
  const host = document.getElementById('customDesignLinkedFields');
  host.innerHTML = '';
  const fields = CardDesignRuntime.linkedFormFields(activeCustomDesign, customSpreadsheetHeaders, record && Array.isArray(record._row) ? record._row : [], [], customColumnMap);
  if (!fields.length) {
    const message = document.createElement('p');
    message.className = 'status';
    message.style.color = '#b42318';
    message.textContent = 'No data fields are mapped for this design. Open Data Sources → Design Mapping, choose the columns, and save the mapping.';
    host.appendChild(message);
    return;
  }
  fields.forEach(function (field) {
    const wrapper = document.createElement('div');
    const label = document.createElement('label');
    const input = document.createElement('input');
    wrapper.className = 'field';
    label.htmlFor = 'customLinkedColumn' + field.columnIndex;
    label.textContent = field.label;
    input.id = 'customLinkedColumn' + field.columnIndex;
    input.className = 'input';
    input.dataset.columnIndex = String(field.columnIndex);
    input.dataset.fieldType = field.type;
    input.value = field.value || '';
    wrapper.appendChild(label);
    wrapper.appendChild(input);
    host.appendChild(wrapper);
  });
}
function collectCustomDesignRecord() {
  return CardDesignRuntime.collectFormValues(document.getElementById('customDesignLinkedFields'));
}
function setRecordModalOpen(isOpen) {
  const modal = document.getElementById('addModal');
  if (!modal) return;
  if (isOpen) {
    modal.style.removeProperty('display');
    modal.hidden = false;
    modal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    window.setTimeout(function () {
      const first = modal.querySelector('[data-column-index]');
      if (first) first.focus();
    }, 0);
  } else {
    modal.hidden = true;
    modal.style.display = 'none';
    modal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
  }
}
function openAdd() {
  editingCustomId = '';
  document.getElementById('recordModalTitle').textContent = 'Add Custom Record';
  document.getElementById('saveButton').textContent = 'Save';
  document.getElementById('deleteRecordButton').hidden = true;
  document.querySelector('#addModal form').reset();
  renderCustomDesignFields(null);
  document.getElementById('addStatus').textContent = '';
  setRecordModalOpen(true);
}
function openEdit() {
  const record = records.find(function (item) {
    return String(item.recordKey || '') === activeId;
  });
  if (!record) return alert('Please select a record first.');
  editingCustomId = activeId;
  document.getElementById('recordModalTitle').textContent = 'Edit Custom Record';
  document.getElementById('saveButton').textContent = 'Save';
  document.getElementById('deleteRecordButton').hidden = false;
  renderCustomDesignFields(record);
  document.getElementById('addStatus').textContent = '';
  setRecordModalOpen(true);
}
function closeAdd() {
  setRecordModalOpen(false);
}
function deleteCurrentRecord() {
  const record = records.find(function (item) {
    return String(item.recordKey || '') === editingCustomId;
  });
  if (!record) return alert('Please select a record first.');
  const fullName = customMappedFullName(record);
  if (!confirm('Delete ' + fullName + ' from the spreadsheet and move matching photos to Drive Trash? The app cannot undo this deletion.')) return;
  const button = document.getElementById('deleteRecordButton');
  const status = document.getElementById('addStatus');
  button.disabled = true;
  status.style.color = '#667085';
  status.textContent = 'Deleting record and photo...';
  google.script.run.withSuccessHandler(function (result) {
    button.disabled = false;
    closeAdd();
    editingCustomId = '';
    populate(result.records || []);
  }).withFailureHandler(function (error) {
    button.disabled = false;
    status.style.color = '#b42318';
    status.textContent = error.message || String(error);
  }).deleteCustomRecord(editingCustomId);
}
function saveRecord(event) {
  event.preventDefault();
  const button = document.getElementById('saveButton');
  const status = document.getElementById('addStatus');
  const originalId = editingCustomId;
  const record = collectCustomDesignRecord();
  if (!Object.keys(record.columnValues).length) {
    status.style.color = '#b42318';
    status.textContent = 'No data fields are mapped for this design. Open Data Sources → Design Mapping before adding or editing a record.';
    return;
  }
  button.disabled = true;
  status.style.color = '#667085';
  status.textContent = originalId ? 'Updating record...' : 'Saving record...';
  const success = function (result) {
    button.disabled = false;
    closeAdd();
    populate(result.records || [], result.savedKey);
    editingCustomId = '';
    event.target.reset();
  };
  const failure = function (error) {
    button.disabled = false;
    status.style.color = '#b42318';
    status.textContent = error.message || String(error);
  };
  const call = google.script.run.withSuccessHandler(success).withFailureHandler(failure);
  if (originalId) call.updateCustomRecord(record, originalId);else call.addCustomRecord(record);
}
function openCamera() {
  if (!activeId) return alert('Please select a record first.');
  cameraTargetIndex = activeId;
  const selectedRecord = records.find(function (item) {
    return String(item.recordKey || '') === activeId;
  });
  cameraTargetName = selectedRecord ? customMappedFullName(selectedRecord) : '';
  if (!cameraTargetName) return alert('This record does not have a mapped full name or mapped first and last name.');
  customCameraWindow = window.open('', 'customCameraWindow', 'width=760,height=760');
  if (!customCameraWindow) {
    alert('Please allow pop-ups to open the camera.');
    return;
  }
  customCameraWindow.document.open();
  customCameraWindow.document.write(\`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Take Custom ID Photo</title>
<style>
* {
  box-sizing:border-box
}
body {
  min-height:100vh;
  margin:0;
  padding:18px;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:center;
  gap:12px;
  font-family:Arial,sans-serif;
  color:#fff;
  background:#111827
}
select {
  width:100%;
  max-width:560px;
  padding:10px;
  color:#fff;
  background:#202938;
  border:1px solid #4b5563;
  border-radius:7px
}
.frame {
  width:330px;
  height:440px;
  max-width:90vw;
  overflow:hidden;
  background:#000;
  border:2px solid #4b5563;
  border-radius:12px
}
video,img {
  width:100%;
  height:100%;
  object-fit:cover
}
.actions {
  display:flex;
  flex-wrap:wrap;
  justify-content:center;
  gap:9px
}
button {
  min-width:110px;
  padding:10px 14px;
  color:#fff;
  border:0;
  border-radius:7px;
  font-weight:700;
  cursor:pointer
}
button:disabled {
  opacity:.55;
  cursor:not-allowed
}
#capture {
  background:#7141c6
}
#retake {
  background:#e67e22
}
#save {
  background:#1f883d
}
#cancel {
  background:#6b7280
}
#status {
  min-height:18px;
  margin:0;
  color:#fdba74;
  text-align:center;
  font-size:13px
}
</style>
</head>
<body>
<select id="cameraSelect" disabled>
<option value="">Loading cameras...</option>
</select>
<p id="status">Allow camera access when prompted, then choose a camera.</p>
<div class="frame">
<video id="video" autoplay playsinline muted>
</video>
<img id="preview" alt="Captured photo" hidden>
</div>
<div class="actions">
<button id="capture" disabled title="Capture the current camera image for review.">Capture Photo</button>
<button id="retake" hidden title="Discard the captured image and return to the camera.">Retake Photo</button>
<button id="save" disabled title="Save this photo to the connected photo folder for the selected record.">Save Photo</button>
<button id="cancel" title="Close without saving these changes.">Cancel</button>
</div>
<script>
const video = document.getElementById('video');
const preview = document.getElementById('preview');
const select = document.getElementById('cameraSelect');
const capture = document.getElementById('capture');
const retake = document.getElementById('retake');
const save = document.getElementById('save');
const status = document.getElementById('status');
let stream = null;
let photo = '';
function stopStream() {
  if (stream) {
    stream.getTracks().forEach(function (track) {
      track.stop();
    });
    stream = null;
  }
}
async function startCamera(deviceId) {
  stopStream();
  capture.disabled = true;
  status.textContent = 'Starting camera...';
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: deviceId ? {
        deviceId: {
          exact: deviceId
        },
        width: {
          ideal: 1280
        },
        height: {
          ideal: 720
        }
      } : {
        width: {
          ideal: 1280
        },
        height: {
          ideal: 720
        }
      },
      audio: false
    });
    video.srcObject = stream;
    await video.play();
    const cameras = (await navigator.mediaDevices.enumerateDevices()).filter(function (device) {
      return device.kind === 'videoinput';
    });
    const current = stream.getVideoTracks()[0].getSettings().deviceId || deviceId || '';
    select.innerHTML = '';
    cameras.forEach(function (camera, index) {
      const option = document.createElement('option');
      option.value = camera.deviceId;
      option.textContent = camera.label || 'Camera ' + (index + 1);
      select.appendChild(option);
    });
    if (!cameras.length) throw new Error('No camera was found. Connect a camera and reopen this window.');
    select.value = current;
    select.disabled = cameras.length < 2;
    capture.disabled = false;
    status.textContent = '';
  } catch (error) {
    select.innerHTML = '<option>Camera unavailable</option>';
    select.disabled = true;
    status.textContent = 'Camera error: ' + (error.message || error);
  }
}
select.addEventListener('change', function () {
  photo = '';
  startCamera(select.value);
});
capture.addEventListener('click', function () {
  if (!video.videoWidth) return;
  const canvas = document.createElement('canvas');
  canvas.width = 360;
  canvas.height = 480;
  const context = canvas.getContext('2d');
  const sourceAspect = video.videoWidth / video.videoHeight;
  const targetAspect = canvas.width / canvas.height;
  let sw;
  let sh;
  let sx;
  let sy;
  if (sourceAspect > targetAspect) {
    sh = video.videoHeight;
    sw = sh * targetAspect;
    sx = (video.videoWidth - sw) / 2;
    sy = 0;
  } else {
    sw = video.videoWidth;
    sh = sw / targetAspect;
    sx = 0;
    sy = (video.videoHeight - sh) / 2;
  }
  context.drawImage(video, sx, sy, sw, sh, 0, 0, canvas.width, canvas.height);
  photo = canvas.toDataURL('image/jpeg', .9);
  preview.src = photo;
  preview.hidden = false;
  video.hidden = true;
  capture.hidden = true;
  retake.hidden = false;
  save.disabled = false;
});
retake.addEventListener('click', function () {
  photo = '';
  preview.hidden = true;
  video.hidden = false;
  capture.hidden = false;
  retake.hidden = true;
  save.disabled = true;
  status.textContent = '';
});
save.addEventListener('click', function () {
  if (!photo) return;
  save.disabled = true;
  status.textContent = 'Saving photo...';
  window.opener.postMessage({
    sessionToken: window.__STUDIO_TOKEN,
    type: 'CUSTOM_CAPTURED_PHOTO',
    dataUrl: photo
  }, '*');
});
document.getElementById('cancel').addEventListener('click', function () {
  stopStream();
  window.close();
});
window.addEventListener('message', function (event) {
  if (!event.data || event.data.type !== 'CUSTOM_PHOTO_RESULT' || event.source !== window.opener) return;
  if (event.data.success) {
    stopStream();
    window.close();
  } else {
    save.disabled = false;
    status.textContent = event.data.error || 'Unable to save photo.';
  }
});
window.addEventListener('beforeunload', stopStream);
if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
  status.textContent = 'This browser does not support camera access.';
} else {
  startCamera('');
}
<\\/script>
</body>
</html>\`);
  customCameraWindow.document.close();
  StudioReliability.registerPopup(customCameraWindow);
}
window.addEventListener('message', function (event) {
  if (!event.data || event.data.type !== 'CUSTOM_CAPTURED_PHOTO') return;
  if (!customCameraWindow || event.source !== customCameraWindow) return;
  const popup = event.source;
  const dataUrl = event.data.dataUrl;
  const targetIndex = cameraTargetIndex;
  const targetName = cameraTargetName;
  const status = document.getElementById('actionStatus');
  google.script.run.withSuccessHandler(function (result) {
    StudioReliability.invalidate();
    if (!result || !result.success) {
      if (popup && !popup.closed) popup.postMessage({
        type: 'CUSTOM_PHOTO_RESULT',
        success: false,
        error: result && result.error || 'Unable to save photo.'
      }, '*');
      return;
    }
    if (activeId === targetIndex) {
      const record = records.find(function (item) {
        return String(item.recordKey || '') === targetIndex;
      });
      if (record && activeCustomDesign) CardDesignRuntime.render(document.getElementById('cardMount'), activeCustomDesign, record, {
        recordId: targetIndex,
        logoData: activeCustomDesign.logoData || logoData,
        photoData: dataUrl
      });
    }
    status.style.color = '#1f883d';
    status.textContent = 'Photo saved as ' + targetName + '.jpg.';
    if (popup && !popup.closed) popup.postMessage({
      type: 'CUSTOM_PHOTO_RESULT',
      success: true
    }, '*');
  }).withFailureHandler(function (error) {
    if (popup && !popup.closed) popup.postMessage({
      type: 'CUSTOM_PHOTO_RESULT',
      success: false,
      error: error.message || String(error)
    }, '*');
  }).saveCustomPhoto(dataUrl, targetIndex);
});
</script>
<style>
#customDesignButton {
  white-space: normal;
  overflow-wrap: anywhere;
  height: auto;
  line-height: 1.4;
}
.studio-sync-status {
  margin: 8px 0;
  color: #475467;
  font-size: 12px;
}
</style>
<script>
// Refresh saved sheet values on returning to this studio; never reload the page.
(function () {
  let timer = null;
  let busy = false;
  let lastStarted = 0;
  let hasLeft = false;
  function recordKey(r) {
    return String(r.recordKey || '');
  }
  function status(message, failed) {
    let node = document.getElementById('studioSyncStatus');
    if (!node) {
      node = document.createElement('p');
      node.id = 'studioSyncStatus';
      node.className = 'studio-sync-status';
      node.setAttribute('role', 'status');
      document.getElementById('cardMount').parentNode.prepend(node);
    }
    node.textContent = message;
    node.style.color = failed ? '#b42318' : '#475467';
  }
  function schedule() {
    if (!hasLeft || document.hidden) return;
    clearTimeout(timer);
    timer = setTimeout(refresh, 900);
  }
  function refresh() {
    if (document.hidden || busy || !configuration.hasSpreadsheet) return;
    if (Date.now() - lastStarted < 2000) return;
    // Leave unfinished edits alone; apply fresh records after the dialog closes.
    if (Array.from(document.querySelectorAll('.modal')).some(function (el) {
      return !el.hidden && getComputedStyle(el).display !== 'none';
    })) {
      timer = setTimeout(refresh, 1500);
      return;
    }
    hasLeft = false;
    busy = true;
    lastStarted = Date.now();
    status('Checking for spreadsheet changes…', false);
    google.script.run.withSuccessHandler(function (data) {
      busy = false;
      if (!Array.isArray(data)) {
        status('Could not read spreadsheet updates.', true);
        return;
      }
      if (JSON.stringify(data) === JSON.stringify(records)) {
        status('Spreadsheet checked. No data changes found.', false);
        return;
      }
      const select = document.getElementById('recordSelect');
      const previous = select.value !== '' ? records[select.value] : null;
      const showingAll = document.getElementById('cardMount').classList.contains('previewing-all');
      const priorNameSearch = window.activeNameSearch;
      let match = previous ? data.find(function (r) {
        return recordKey(r) === recordKey(previous);
      }) : null;
      if (!match && previous) {
        const sameName = data.filter(function (r) {
          return customMappedFullName(r) === customMappedFullName(previous);
        });
        if (sameName.length === 1) match = sameName[0];
      }
      populate(data, match ? recordKey(match) : '');
      if (priorNameSearch) {
        const input = document.getElementById('customRecordSearchInput');
        input.value = priorNameSearch;
        searchCustomRecord();
      } else if (showingAll && data.length) previewAllCustomCards();
      status(previous && !match && !showingAll ? 'Spreadsheet updated. Please select the record again; its identifying details changed or it was removed.' : 'Spreadsheet data reloaded. Any displayed card uses the updated values.', false);
    }).withFailureHandler(function (error) {
      busy = false;
      hasLeft = true;
      status('Unable to update spreadsheet data: ' + (error.message || String(error)) + '. Switch back to this tab to retry.', true);
    }).getCustomData();
  }
  window.addEventListener('blur', function () {
    hasLeft = true;
  });
  window.addEventListener('focus', schedule);
  // Also works when the Apps Script iframe itself does not receive window focus.
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) hasLeft = true;else schedule();
  });
  document.addEventListener('pointerdown', schedule);
})();
</script>
<?!= include('ReliabilityClient'); ?>
</body>
</html>
`;

    case 'Design':
      return `<!DOCTYPE html>
<html>
<head>
<script>
window.STUDIO_URL = <?!= JSON.stringify(webAppUrl) ?>;
window.STUDIO_TYPE = <?!= JSON.stringify(studioType) ?>;
window.STUDIO_SCOPE = <?!= JSON.stringify(clientScope) ?>;
window.STUDIO_STORAGE = {
  getItem: function (k) {
    return localStorage.getItem(STUDIO_SCOPE + k);
  },
  setItem: function (k, v) {
    localStorage.setItem(STUDIO_SCOPE + k, v);
  },
  removeItem: function (k) {
    localStorage.removeItem(STUDIO_SCOPE + k);
  }
};
</script>
<base target="_top">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdn.jsdelivr.net/npm/jsbarcode@3.11.5/dist/JsBarcode.all.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js"></script>
<style>
:root {
  --ink:#172033;
  --muted:#667085;}
* {
  box-sizing:border-box
}
[hidden] {
  display:none!important
}
body {
  min-height:100vh;
  margin:0;
  font-family:"Segoe UI",Arial,sans-serif;}
button,input,select {
  font:inherit
}
.topbar {
  align-items:center;
  justify-content:space-between;
  gap:14px;}
.brand {
  display:flex;
  align-items:center;
  gap:10px;
  flex:0 0 auto
}
.mark {
  display:grid;
  place-items:center;
  color:#fff;
  font-weight:900
}
.brand h1 {
  margin:0;}
.brand p {
  margin:2px 0 0;
  color:var(--muted);}
.actions {
  display:flex;
  flex-wrap:wrap;
  gap:7px;
  flex:0 0 auto
}
.btn {
  color:#344054;
  background:#fff;
  border:1px solid var(--line);
  font-weight:750;
  cursor:pointer
}
.btn.primary {
  color:#fff;}
.home {
  text-decoration:none
}
.top-album {
  flex:1;}
.top-album-title {
  display:block;
  margin-bottom:6px;
  font-weight:800;
  letter-spacing:.07em;
  text-transform:uppercase
}
.top-album-controls {
  display:grid;
  gap:6px;
  align-items:center
}
.top-album .btn,.top-album .input {
  min-height:32px;
  padding:5px 8px
}
.top-album .status {
  min-height:0
}
.app {
  display:grid;}
.sidebar {
  overflow:auto
}
.section {
  padding-bottom:15px;
  margin-bottom:15px;
  border-bottom:1px solid #edf0f4
}
.section h2 {
  margin:0 0 10px;
  letter-spacing:.08em;
  text-transform:uppercase
}
.label {
  display:flex;
  justify-content:space-between;
  font-weight:750
}
.input {
  width:100%;
  background:#fff;
  border:1px solid #cbd5e1;
  outline:none;}
.palette {
  display:flex;
  flex-direction:column;
  gap:7px
}
.palette-row {
  display:grid;
  grid-template-columns:112px minmax(0,1fr);
  gap:6px
}
.palette-row .btn {
  min-height:38px;
  text-align:left
}
.column-select {
  min-width:0;
  min-height:38px;
  padding:6px;
  color:#344054;
  background:#fff;
  border:1px solid #cbd5e1;
  border-radius:7px;
  font-size:11px
}
.hint {
  margin:8px 0 0;
  color:var(--muted);
  font-size:11px;
  line-height:1.4
}
.saved-row {
  display:flex;
  gap:6px
}
.saved-row .input {
  min-width:0
}
.layers {
  display:flex;
  flex-direction:column;
  gap:5px;
  overflow:auto
}
.layer {
  width:100%;
  display:flex;
  justify-content:space-between;
  color:#344054;
  border:1px solid transparent;
  border-radius:6px;
  font-size:11px;
  cursor:pointer
}
.workspace {
  min-width:0;
  overflow:auto;}
.workspace-head {
  justify-content:space-between;
  gap:10px
}
.workspace-head span {
  color:var(--muted);}
.card-shell {
  display:grid;}
.design-card {
  position:relative;
  overflow:hidden;
  background:#fff;
  border:1px solid #98a2b3;
  border-radius:12px;
  touch-action:none
}
.lanyard {
  width:56px;
  height:12px;
  position:absolute;
  z-index:999;
  top:7px;
  left:50%;
  transform:translateX(-50%);
  background:#e4eaf2;
  border:1px solid #98a2b3;
  border-radius:8px;
  pointer-events:none
}
.design-element {
  position:absolute;
  min-width:20px;
  min-height:18px;
  display:flex;
  align-items:center;
  justify-content:center;
  overflow:visible;
  user-select:none;
  touch-action:none;
  cursor:move;
  transform-origin:center
}
.design-element.selected {
  outline-offset:1px
}
.design-element img {
  width:100%;
  height:100%;
  display:block;
  object-fit:contain;
  pointer-events:none
}
.design-element.photo {
  border:1px dashed #7b8ba4;
  border-radius:7px;
  background:#f3f6fa
}
.design-element.photo img {
  object-fit:cover
}
.photo-placeholder {
  width:100%;
  height:100%;
  display:grid;
  place-items:center;
  color:#667085;
  background:linear-gradient(145deg,#d7e5f2,#f0d8c9);
  font-size:11px;
  font-weight:750
}
.resize-handle {
  cursor:nwse-resize;}
.barcode-svg {
  width:100%;
  height:100%;
  display:block
}
.class-content {
  width:100%;
  justify-content:center;
  gap:4px;
  white-space:nowrap
}
.transport-icon {
  width:100%;
  height:100%;
  display:flex;
  align-items:center;
  justify-content:center
}
.transport-icon svg {
  width:90%;
  height:90%
}
.empty-state {
  font-size:12px;
  text-align:center
}
.inline {
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:7px
}
.check {
  display:flex;
  align-items:center;
  gap:7px;
  color:#344054;
  font-size:12px
}
.inspector-actions {
  display:grid;
  grid-template-columns:1fr 1fr;}
.status {
  min-height:17px;
  margin:8px 0 0;
  color:#1f883d;
  font-size:11px;
  font-weight:700
}
.status.error {
  color:#b42318
}
.subpanel {
  padding:10px;
  margin:8px 0 10px;
  background:#f7f9fc;
  border:1px solid #e4e9f0;
  border-radius:8px
}
.subpanel h3 {
  margin:0 0 8px;
  font-size:11px
}
.source-badge {
  margin-bottom:10px;
  border:1px solid #b2ddff;
  font-size:11px;
  line-height:1.35
}
.palette-row.no-column .btn {
  grid-column:1/-1
}
.new-element-btn {
  width:100%;
  color:#fff;}
.element-picker {
  border-radius:9px
}
.element-option-grid {
  display:grid;}
.element-option-grid button {
  font-weight:700;
  cursor:pointer
}
.collapsible {
  padding-top:0
}
.collapsible summary {
  font-weight:800;
  letter-spacing:.08em;
  text-transform:uppercase;
  cursor:pointer;
  list-style:none
}
.collapsible summary::-webkit-details-marker {
  display:none
}
.collapsible summary::after {
  content:'+';
  float:right;
  color:var(--blue);}
.collapsible[open] summary::after {
  content:'−'
}
.section-body {
  padding-top:2px
}
.format-toolbar {
  display:flex;
  flex-wrap:wrap;
  gap:4px;
  padding:7px;
  margin-bottom:10px;
  background:#f7f9fc;
  border:1px solid #e0e6ee;
  border-radius:8px
}
.tool-btn {
  width:29px;
  height:29px;
  padding:0;
  display:grid;
  place-items:center;
  color:#344054;
  background:#fff;
  border:1px solid #ccd5e0;
  border-radius:5px;
  font-size:12px;
  font-weight:750;
  cursor:pointer
}
.tool-btn.active {
  color:#fff;
  background:var(--blue);
  border-color:var(--blue)
}
.tool-size {
  display:grid;
  place-items:center;
  background:#fff;
  border:1px solid #ccd5e0;
  font-size:11px
}
.tool-color {
  width:29px;
  height:29px;
  padding:3px;
  background:#fff;
  border:1px solid #ccd5e0;
  border-radius:5px;
  cursor:pointer
}
.tool-separator {
  width:1px;
  height:25px;
  margin:2px 2px;
  background:#d8e0ea
}
.opacity-tool {
  width:100%;
  display:grid;
  grid-template-columns:50px 1fr 34px;
  gap:5px;
  align-items:center;
  color:#667085;
  font-size:10px
}
.opacity-tool input {
  width:100%
}
.class-content {
  height:100%;
  display:grid!important;
  grid-template-columns:minmax(0,1fr) minmax(0,1fr);
  align-items:stretch!important
}
.grade-segment {
  min-width:0;
  height:100%;
  display:flex;
  overflow:hidden
}
.resize-handle {
  position:absolute;
  right:auto;
  bottom:auto;
  z-index:20
}
.resize-handle.nw {
  left:0;
  top:0;
  transform:translate(-50%,-50%);
  cursor:nwse-resize
}
.resize-handle.n {
  left:50%;
  top:0;
  transform:translate(-50%,-50%);
  cursor:ns-resize
}
.resize-handle.ne {
  right:0;
  top:0;
  left:auto;
  transform:translate(50%,-50%);
  cursor:nesw-resize
}
.resize-handle.e {
  right:0;
  top:50%;
  left:auto;
  transform:translate(50%,-50%);
  cursor:ew-resize
}
.resize-handle.se {
  right:0;
  bottom:0;
  left:auto;
  top:auto;
  transform:translate(50%,50%);
  cursor:nwse-resize
}
.resize-handle.s {
  left:50%;
  bottom:0;
  top:auto;
  transform:translate(-50%,50%);
  cursor:ns-resize
}
.resize-handle.sw {
  left:0;
  bottom:0;
  top:auto;
  transform:translate(-50%,50%);
  cursor:nesw-resize
}
.resize-handle.w {
  left:0;
  top:50%;
  transform:translate(-50%,-50%);
  cursor:ew-resize
}
@media(max-width:930px) {
  .app {
    grid-template-columns:225px minmax(330px,1fr)
  }
  .right {
    grid-column:1/-1;
    border-left:0;
    border-top:1px solid var(--line);
    display:grid;
    grid-template-columns:repeat(2,1fr);
    gap:14px
  }
}
@media(max-width:650px) {
  .app {
    display:block
  }
  .left,.right {
    border:0;
    border-bottom:1px solid var(--line)
  }
  .right {
    display:block
  }
  .workspace {
    padding:16px 8px
  }
  .design-card.landscape-card {
    transform:scale(.9);
    transform-origin:top center
  }
}
@media print {
  @page {
    margin:0
  }
  body {
    background:transparent
  }
  .topbar,.sidebar,.workspace-head {
    display:none!important
  }
  .app,.workspace,.card-shell {
    display:block!important;
    min-height:0!important;
    padding:0!important;
    background:transparent!important
  }
  .design-card {
    border:0!important;
    border-radius:0!important;
    box-shadow:none!important
  }
  .design-element.selected {
    outline:0
  }
  .resize-handle {
    display:none
  }
  .lanyard {
    background:transparent;
    border-color:transparent
  }
}
.inspector-label {
  margin:14px 0 7px;
  padding-top:10px;
  border-top:1px solid #edf0f4;
  font-size:10px;
  font-weight:850;
  letter-spacing:.08em;
  text-transform:uppercase
}
.element-text {
  width:100%;
  min-width:0;
  max-width:100%;
  max-height:100%;
  display:block;
  padding:1px 2px;
  line-height:1.08;
  white-space:normal;
  overflow-wrap:anywhere;
  word-break:normal;
  overflow:hidden
}
.element-text.justify,.element-text.auto-justified {
  text-align:justify;
  text-align-last:auto;
  text-justify:inter-word
}
.alignment-panel {
  padding:9px;
  margin:-4px 0 10px;
  background:#f7f9fc;
  border:1px solid #e0e6ee;
  border-radius:8px
}
.alignment-title {
  margin:0 0 6px;
  color:#475467;
  font-size:10px;
  font-weight:800
}
.alignment-grid {
  display:grid;
  grid-template-columns:repeat(4,1fr);
  gap:5px
}
.alignment-grid.vertical {
  grid-template-columns:repeat(3,1fr);
  margin-top:7px
}
.alignment-grid .btn {
  min-height:32px;
  padding:5px;
  font-size:10px
}
.alignment-grid .btn.active {
  color:#fff;
  background:var(--blue);
  border-color:var(--blue)
}
#toolbarAlignLeft,#toolbarAlignCenter,#toolbarAlignRight,#toolbarVTop,#toolbarVMiddle,#toolbarVBottom {
  display:none
}
.side-tabs {
  max-width:720px;
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:6px;
  border-radius:9px
}
.side-tab {
  color:#475467;
  background:#f7f9fc;
  border:1px solid transparent;
  border-radius:6px;
  font-size:12px;
  font-weight:800;
  cursor:pointer
}
.side-tab.active {
  color:#fff;
  background:var(--blue);
  box-shadow:0 2px 7px rgba(24,90,219,.28)
}
/* 2026 Design Studio visual refresh */
:root {
  --navy:#102a56;
  --blue:#2563eb;
  --blue-dark:#1748b5;
  --violet:#6d4aff;
  --surface:#ffffff;
  --soft:#f5f7fb;
  --line:#d9e1ec;
  --shadow:0 8px 24px rgba(16,42,86,.09)
}
body {
  background:#edf2f8;
  color:#17233a
}
.topbar {
  min-height:auto;
  padding:0;
  display:block;
  position:sticky;
  top:0;
  z-index:1000;
  background:#fff;
  border-bottom:1px solid #d7e0eb;
  box-shadow:0 4px 18px rgba(16,42,86,.08)
}
.topbar-main {
  min-height:72px;
  padding:11px 20px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:18px
}
.brand {
  min-width:280px
}
.mark {
  width:46px;
  height:46px;
  border-radius:14px;
  background:linear-gradient(145deg,#e66a13,#f3a11a);
  box-shadow:0 7px 16px rgba(230,106,19,.25)
}
.mark svg {
  width:35px;
  height:35px;
  display:block;
  filter:drop-shadow(0 2px 3px rgba(23,32,51,.24))
}
.brand h1 {
  font-size:21px;
  color:var(--navy);
  letter-spacing:-.02em
}
.brand p {
  margin-top:3px;
  font-size:12px
}
.actions {
  justify-content:flex-end
}
.btn {
  min-height:38px;
  padding:8px 13px;
  border-color:#cfd9e6;
  border-radius:9px;
  font-size:12px;
  transition:transform .15s,box-shadow .15s,background .15s,border-color .15s
}
.btn:hover {
  border-color:#9fb1c9;
  background:#f7f9fc;
  box-shadow:0 3px 9px rgba(16,42,86,.08);
  transform:translateY(-1px)
}
.btn.primary {
  background:linear-gradient(135deg,#2563eb,#1748b5);
  border-color:#1748b5
}
.btn.primary:hover {
  background:linear-gradient(135deg,#1d55d5,#123d9d)
}
.btn.danger {
  color:#b42318;
  background:#fff7f6;
  border-color:#f4c7c3
}
.home {
  display:inline-flex;
  align-items:center;
  color:#fff!important;
  background:#17233a!important;
  border-color:#17233a!important;
  border-radius:9px
}
.home:hover {
  color:#fff!important;
  background:#101a2c!important;
  border-color:#101a2c!important
}
.top-album {
  min-width:0;
  max-width:none;
  padding:9px 20px;
  display:grid;
  grid-template-columns:auto minmax(420px,760px) minmax(160px,1fr);
  gap:14px;
  align-items:center;
  background:#f4f7fc;
  border:0;
  border-top:1px solid #e4eaf2;
  border-radius:0
}
.top-album-title {
  margin:0;
  color:#344767;
  font-size:11px;
  white-space:nowrap
}
.top-album-controls {
  grid-template-columns:auto minmax(180px,1fr) auto auto
}
.top-album .status {
  margin:0;
  text-align:right;
  line-height:1.25
}
.app {
  height:calc(100vh - 130px);
  min-height:640px;
  grid-template-columns:320px minmax(420px,1fr) 348px;
  gap:0
}
.sidebar {
  padding:18px;
  background:#f8fafc;
  scrollbar-width:thin
}
.left {
  border-right:1px solid #d9e1ec
}
.right {
  border-left:1px solid #d9e1ec
}
.panel-heading {
  margin:0 0 14px
}
.panel-heading strong {
  display:block;
  color:var(--navy);
  font-size:15px
}
.panel-heading span {
  display:block;
  margin-top:3px;
  color:#77849a;
  font-size:11px;
  line-height:1.4
}
.section {
  padding:14px;
  margin:0 0 13px;
  background:#fff;
  border:1px solid #dce4ee;
  border-radius:12px;
  box-shadow:0 3px 12px rgba(16,42,86,.045)
}
.section:last-child {
  margin-bottom:0
}
.section h2 {
  margin-bottom:12px;
  color:#344767;
  font-size:11px
}
.collapsible summary {
  padding:1px 0 11px;
  color:#243b60;
  font-size:11px
}
.collapsible summary::after {
  width:22px;
  height:22px;
  display:grid;
  place-items:center;
  margin-top:-4px;
  background:#edf3ff;
  border-radius:6px;
  font-size:16px;
  line-height:1
}
.field {
  margin-bottom:12px
}
.label {
  margin-bottom:6px;
  color:#33455f;
  font-size:11px
}
.input {
  min-height:40px;
  padding:8px 10px;
  border-color:#cbd7e6;
  border-radius:8px;
  font-size:12px
}
.input:hover {
  border-color:#9eb0c8
}
.input:focus {
  border-color:#2563eb;
  box-shadow:0 0 0 3px rgba(37,99,235,.12)
}
input[type=color].input {
  padding:5px
}
.source-badge {
  padding:9px 10px;
  color:#175cd3;
  background:#eef6ff;
  border-color:#b8d7ff;
  border-radius:8px
}
.new-element-btn {
  min-height:42px;
  margin-top:0;
  background:linear-gradient(135deg,#6d4aff,#5131ce);
  border-color:#5131ce
}
.element-option-grid button::before {
  font-weight:900
}
.layers {
  max-height:260px
}
.layer {
  min-height:36px;
  padding:8px 10px;
  background:#f8fafc;
  border-color:#edf1f5
}
.layer:hover {
  border-color:#b7c8df
}
.layer.active {
  color:#1748b5;
  background:#eaf2ff;
  border-color:#8db4f6;
  box-shadow:inset 3px 0 #2563eb
}
.workspace {
  padding:18px 24px 34px;
  background-color:#dfe7f1;
  background-image:radial-gradient(rgba(55,73,99,.22) 1px,transparent 1px);
  background-size:20px 20px
}
.canvas-toolbar {
  width:100%;
  max-width:none;
  margin:0 auto 14px;
  padding:12px 14px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:14px;
  background:rgba(255,255,255,.94);
  border:1px solid #d2dce8;
  border-radius:12px;
  box-shadow:var(--shadow);
  backdrop-filter:blur(8px)
}
.workspace-head {
  max-width:none;
  margin:0;
  display:block
}
.workspace-head strong {
  display:block;
  color:var(--navy);
  font-size:14px
}
.workspace-head span {
  display:block;
  margin-top:3px;
  font-size:11px
}
.side-tabs {
  width:250px;
  margin:0;
  padding:4px;
  background:#e6ebf3
}
.side-tab {
  padding:8px
}
.card-shell {
  min-height:500px;
  padding:28px 22px;
  place-items:start center;
  background:rgba(255,255,255,.38);
  border:1px solid rgba(174,189,208,.72);
  border-radius:15px
}
.design-card {
  box-shadow:0 20px 42px rgba(16,42,86,.22),0 2px 5px rgba(16,42,86,.12)
}
.design-element.selected {
  outline:2px solid #2563eb;
  box-shadow:0 0 0 3px rgba(37,99,235,.14)
}
.resize-handle {
  width:16px;
  height:16px;
  background:#2563eb;
  border:3px solid #fff;
  border-radius:50%;
  box-shadow:0 1px 5px rgba(16,42,86,.35)
}
.design-element.photo {
  overflow:visible
}
.design-element.photo>img,.design-element.photo>.photo-placeholder {
  border-radius:inherit;
  overflow:hidden
}
.design-element.image>img {
  object-fit:fill
}
.right .section:first-child {
  min-height:180px
}
.empty-state {
  padding:24px 12px;
  color:#7a8799;
  background:#f8fafc;
  border:1px dashed #cbd6e3;
  border-radius:9px
}
.inspector-label {
  margin-top:17px;
  color:#53657e
}
.format-toolbar,.alignment-panel,.subpanel {
  background:#f7f9fc;
  border-color:#dce4ee;
  border-radius:9px
}
.tool-btn,.tool-size,.tool-color {
  border-color:#c8d4e2
}
.tool-btn:hover {
  color:#1748b5;
  border-color:#8fb1e7;
  background:#edf4ff
}
.inspector-actions {
  gap:8px
}
.inspector-actions .btn {
  min-height:39px
}
@media(max-width:1180px) {
  .app {
    grid-template-columns:270px minmax(380px,1fr) 315px
  }
  .topbar-main {
    align-items:flex-start
  }
  .brand p {
    display:none
  }
  .actions {
    max-width:610px
  }
  .top-album {
    grid-template-columns:auto 1fr
  }
  .top-album .status {
    grid-column:1/-1;
    text-align:left
  }
  .canvas-toolbar {
    align-items:flex-start;
    flex-direction:column
  }
  .side-tabs {
    width:100%
  }
}
@media(max-width:900px) {
  .topbar {
    position:static
  }
  .topbar-main {
    display:block
  }
  .brand {
    margin-bottom:11px
  }
  .actions {
    justify-content:flex-start;
    max-width:none
  }
  .top-album {
    display:block
  }
  .top-album-title {
    margin-bottom:7px
  }
  .top-album-controls {
    grid-template-columns:auto minmax(120px,1fr) auto auto
  }
  .app {
    height:auto;
    display:block
  }
  .sidebar {
    overflow:visible
  }
  .workspace {
    min-height:600px
  }
  .right {
    border-top:1px solid var(--line)
  }
  .panel-heading {
    margin-top:2px
  }
}
@media(max-width:560px) {
  .topbar-main,.top-album {
    padding-left:12px;
    padding-right:12px
  }
  .actions {
    display:grid;
    grid-template-columns:1fr 1fr
  }
  .actions .btn {
    text-align:center
  }
  .top-album-controls {
    grid-template-columns:1fr 1fr
  }
  .top-album-controls .input {
    grid-column:1/-1;
    grid-row:1
  }
  .workspace {
    padding:12px 7px
  }
  .canvas-toolbar {
    padding:10px
  }
  .card-shell {
    padding:22px 5px
  }
  .element-option-grid {
    grid-template-columns:1fr
  }
}
@media print {
  .canvas-toolbar {
    display:block!important;
    padding:0!important;
    margin:0!important;
    border:0!important;
    box-shadow:none!important
  }
  .canvas-toolbar .workspace-head,.side-tabs {
    display:none!important
  }
  .card-shell {
    padding:0!important;
    border:0!important;
    background:transparent!important
  }
}
.quick-guide {
  padding:10px 12px;
  margin-bottom:13px;
  color:#314563;
  background:#eef5ff;
  border:1px solid #c9dcfb;
  border-radius:10px;
  font-size:11px;
  line-height:1.5
}
.quick-guide strong {
  color:#1748b5
}
.step-title {
  display:flex;
  align-items:center;
  gap:8px
}
.step-number {
  width:23px;
  height:23px;
  display:inline-grid;
  place-items:center;
  flex:0 0 auto;
  color:#fff;
  background:#2563eb;
  border-radius:50%;
  font-size:11px;
  font-weight:900;
  letter-spacing:0
}
.collapsible>summary {
  display:flex;
  align-items:center;
  justify-content:space-between
}
.collapsible>summary::after {
  float:none;
  flex:0 0 auto;
  margin-left:8px
}
.simple-details {
  padding:0;
  margin:8px 0 0;
  border:1px solid #dce4ee;
  border-radius:9px;
  background:#fafcff
}
.simple-details>summary {
  padding:10px 11px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  color:#405572;
  font-size:11px;
  font-weight:800;
  cursor:pointer;
  list-style:none
}
.simple-details>summary::-webkit-details-marker {
  display:none
}
.simple-details>summary::after {
  content:'＋';
  color:#2563eb
}
.simple-details[open]>summary::after {
  content:'−'
}
.simple-details-body {
  padding:2px 11px 11px;
  border-top:1px solid #e7edf4
}
.simple-details-body>.field:first-child {
  margin-top:10px
}
.top-album-toggle {
  padding:0 20px;
  background:#f4f7fc;
  border-top:1px solid #e4eaf2
}
.top-album-toggle>summary {
  padding:9px 0;
  color:#405572;
  font-size:11px;
  font-weight:800;
  cursor:pointer;
  list-style:none
}
.top-album-toggle>summary::-webkit-details-marker {
  display:none
}
.top-album-toggle>summary::before {
  content:'▸';
  display:inline-block;
  margin-right:7px;
  color:#2563eb
}
.top-album-toggle[open]>summary::before {
  content:'▾'
}
.top-album-toggle .top-album {
  padding:0 0 10px;
  border:0
}
.header-status {
  padding:7px 20px;
  margin:0;
  background:#f4f7fc;
  border-top:1px solid #e4eaf2
}
.header-status:empty {
  display:none
}
.beginner-note {
  margin:0 0 10px;
  color:#667085;
  font-size:11px;
  line-height:1.45
}
.selected-name {
  padding:8px 10px;
  margin-bottom:11px;
  color:#1748b5;
  background:#edf4ff;
  border-radius:8px;
  font-size:11px;
  font-weight:800
}
.control-heading {
  margin:2px 0 10px;
  color:#1f3658;
  font-size:12px;
  font-weight:850
}
.element-picker {
  padding:0;
  margin-top:0;
  background:transparent;
  border:0
}
.element-option-grid {
  grid-template-columns:1fr 1fr;
  gap:8px
}
.element-option-grid button {
  min-height:42px;
  padding:8px 9px;
  display:flex;
  align-items:center;
  color:#263b5a;
  background:#f8fbff;
  border:1px solid #ccd9e9;
  border-radius:9px;
  font-size:11px;
  text-align:left
}
.element-option-grid button::before {
  content:'＋';
  width:21px;
  height:21px;
  display:grid;
  place-items:center;
  flex:0 0 auto;
  margin-right:7px;
  color:#fff;
  background:#2563eb;
  border-radius:6px;
  font-size:14px
}
.element-option-grid button:hover {
  color:#1748b5;
  background:#eaf2ff;
  border-color:#79a5ed;
  box-shadow:0 3px 9px rgba(37,99,235,.1)
}
.clear-tools {
  display:block;
  padding:10px
}
.format-control {
  padding-bottom:10px;
  margin-bottom:10px;
  border-bottom:1px solid #e1e7ef
}
.format-name {
  display:block;
  margin-bottom:7px;
  color:#405572;
  font-size:10px;
  font-weight:850;
  text-transform:uppercase;
  letter-spacing:.05em
}
.format-buttons {
  display:grid;
  grid-template-columns:1fr 42px 1fr;
  gap:6px
}
.format-buttons.four {
  grid-template-columns:1fr 1fr
}
.tool-btn.labeled {
  width:auto;
  height:34px;
  padding:6px 8px;
  display:flex;
  align-items:center;
  justify-content:center;
  font-size:10px
}
.tool-size {
  width:auto;
  height:34px;
  border-radius:6px
}
.color-controls {
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:8px
}
.color-controls label {
  display:grid;
  grid-template-columns:1fr 38px;
  align-items:center;
  gap:5px;
  padding:6px 7px;
  color:#405572;
  background:#fff;
  border:1px solid #d3dde9;
  border-radius:7px;
  font-size:10px;
  font-weight:750
}
.color-controls .tool-color {
  width:34px;
  height:28px
}
.color-controls .tool-btn {
  grid-column:1/-1
}
.clear-tools .opacity-tool {
  grid-template-columns:72px 1fr 38px;
  font-size:10px
}
.design-tabs-wrap {
  width:100%;
  max-width:none;
  margin:0 auto 10px;
  padding:7px;
  display:flex;
  align-items:center;
  gap:8px;
  background:#cfd9e6;
  border:1px solid #bdc9d8;
  border-radius:11px;
  box-shadow:0 4px 12px rgba(16,42,86,.08)
}
.design-tabs-label {
  padding-left:4px;
  color:#405572;
  font-size:10px;
  font-weight:850;
  letter-spacing:.05em;
  text-transform:uppercase;
  white-space:nowrap
}
.design-tabs {
  min-width:0;
  display:flex;
  gap:6px;
  overflow-x:auto;
  scrollbar-width:thin
}
.design-tab {
  min-width:130px;
  max-width:220px;
  height:38px;
  padding:0 7px 0 11px;
  display:flex;
  align-items:center;
  gap:7px;
  color:#405572;
  background:#f7f9fc;
  border:1px solid transparent;
  border-radius:8px;
  cursor:pointer
}
.design-tab:hover {
  background:#fff;
  border-color:#aebed2
}
.design-tab.active {
  color:#1748b5;
  background:#fff;
  border-color:#8db4f6;
  box-shadow:0 2px 7px rgba(37,99,235,.16)
}
.design-tab-name {
  min-width:0;
  flex:1;
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
  font-size:11px;
  font-weight:800;
  text-align:left
}
.design-tab-close {
  width:22px;
  height:22px;
  padding:0;
  display:grid;
  place-items:center;
  flex:0 0 auto;
  color:#7b8798;
  background:transparent;
  border:0;
  border-radius:5px;
  font-size:16px;
  line-height:1;
  cursor:pointer
}
.design-tab-close:hover {
  color:#b42318;
  background:#fff0ee
}
.qr-code {
  width:100%;
  height:100%;
  display:grid;
  place-items:center;
  background:#fff
}
.qr-code svg {
  width:100%;
  height:100%;
  display:block
}
.font-size-tools {
  display:grid;
  grid-template-columns:1fr 52px 1fr;
  gap:7px
}
.icon-tool-grid {
  display:grid;
  grid-template-columns:repeat(4,1fr);
  gap:7px
}
.tool-btn.icon-tool {
  width:auto;
  height:38px;
  padding:0;
  display:grid;
  place-items:center;
  font-size:14px
}
.color-icon-tool {
  height:38px;
  position:relative;
  display:grid;
  place-items:center;
  background:#fff;
  border:1px solid #c8d4e2;
  border-radius:6px;
  cursor:pointer;
  overflow:hidden
}
.color-icon-tool:hover {
  border-color:#8fb1e7;
  background:#edf4ff
}
.color-icon-tool input {
  position:absolute;
  inset:0;
  width:100%;
  height:100%;
  opacity:0;
  cursor:pointer
}
.text-color-symbol {
  color:var(--picked-color,#111827);
  font-size:18px;
  font-weight:900;
  text-decoration:underline;
  text-decoration-color:var(--picked-color,#111827);
  text-decoration-thickness:3px;
  text-underline-offset:2px
}
.box-color-symbol {
  width:21px;
  height:15px;
  border:2px solid #344054;
  background:var(--picked-color,#dbe7f7);
  border-radius:2px
}
.visual-align {
  padding:0!important;
  margin:0 0 10px!important;
  background:transparent!important;
  border:0!important
}
.visual-align-grid {
  display:grid;
  gap:7px
}
.visual-align-grid.four {
  grid-template-columns:repeat(4,1fr)
}
.visual-align-grid.three {
  grid-template-columns:repeat(3,1fr)
}
.vertical-name {
  margin-top:10px
}
.align-icon {
  width:auto!important;
  height:38px!important
}
.lines {
  width:20px;
  height:14px;
  position:relative;
  display:block
}
.lines::before,.lines::after {
  content:'';
  height:2px;
  position:absolute;
  background:#344054;
  border-radius:2px
}
.lines::before {
  width:20px;
  top:2px;
  left:0;
  box-shadow:0 9px 0 #344054
}
.lines::after {
  width:13px;
  top:7px
}
.lines.left::after {
  left:0
}
.lines.center::after {
  left:3.5px
}
.lines.right::after {
  right:0
}
.lines.justify::after {
  width:20px;
  left:0
}
.v-lines {
  width:23px;
  height:20px;
  position:relative;
  display:block;
  border:1px solid #b8c4d4;
  border-radius:3px
}
.v-lines::before {
  content:'';
  width:15px;
  height:5px;
  position:absolute;
  left:3px;
  border-top:2px solid #344054;
  border-bottom:2px solid #344054
}
.v-lines.top::before {
  top:3px
}
.v-lines.middle::before {
  top:6px
}
.v-lines.bottom::before {
  bottom:3px
}
.rotate-handle {
  width:25px;
  height:25px;
  position:absolute;
  left:50%;
  top:-31px;
  transform:translateX(-50%);
  display:grid;
  place-items:center;
  color:#fff;
  background:#6d4aff;
  border:3px solid #fff;
  border-radius:50%;
  box-shadow:0 2px 7px rgba(16,42,86,.35);
  font-size:16px;
  font-weight:900;
  line-height:1;
  cursor:grab;
  z-index:30;
  touch-action:none
}
.rotate-handle::before {
  content:attr(data-angle);
  position:absolute;
  left:31px;
  top:0;
  min-width:38px;
  padding:4px 6px;
  color:#35245f;
  background:#fff;
  border:1px solid #c9b9e8;
  border-radius:6px;
  box-shadow:0 2px 7px rgba(16,42,86,.14);
  font-size:10px;
  font-weight:900;
  line-height:1;
  text-align:center
}
.rotate-handle::after {
  content:'';
  width:2px;
  height:8px;
  position:absolute;
  left:50%;
  top:22px;
  transform:translateX(-50%);
  background:#6d4aff
}
.rotate-handle:active {
  cursor:grabbing
}
.transport-help {
  padding:12px;
  margin:10px 0;
  background:#f8fbff;
  border:1px solid #cbdcf4;
  border-radius:10px
}
.transport-help h3 {
  margin:0 0 5px;
  color:#1f3658;
  font-size:12px
}
.transport-help-intro {
  margin:0 0 10px;
  color:#5c6f89;
  font-size:10px;
  line-height:1.45
}
.transport-rule {
  display:grid;
  grid-template-columns:30px 1fr;
  gap:8px;
  padding:8px 0;
  border-top:1px solid #e1e9f3
}
.transport-rule:first-of-type {
  border-top:0
}
.transport-rule-icon {
  width:28px;
  height:28px;
  display:grid;
  place-items:center;
  background:#fff;
  border:1px solid #d4dfec;
  border-radius:7px
}
.transport-rule-icon svg {
  width:21px;
  height:21px
}
.transport-emoji {
  font-size:19px;
  line-height:1
}
.transport-rule strong {
  display:block;
  margin-bottom:3px;
  color:#263b5a;
  font-size:10px
}
.transport-rule .input {
  min-height:31px;
  padding:5px 7px;
  font-size:10px
}
.transport-none-icon {
  color:#667085;
  font-size:18px;
  font-weight:900
}
.transport-help-note {
  margin:8px 0 0;
  color:#667085;
  font-size:9px;
  line-height:1.4
}
.grade-color-panel {
  padding:11px;
  margin:10px 0;
  background:#f7f5ff;
  border:1px solid #d9ccf3;
  border-radius:9px
}
.grade-color-panel h3 {
  margin:0 0 4px;
  color:#35245f;
  font-size:12px
}
.grade-color-panel>p {
  margin:0 0 10px;
  color:#667085;
  font-size:10px;
  line-height:1.4
}
.grade-part {
  padding:9px;
  margin-top:8px;
  background:#fff;
  border:1px solid #ded7ec;
  border-radius:8px
}
.grade-part-title {
  display:block;
  margin-bottom:8px;
  color:#35245f;
  font-size:10px;
  font-weight:900;
  text-transform:uppercase;
  letter-spacing:.04em
}
.tool-subheading {
  display:block;
  padding-top:8px;
  margin:9px 0 8px;
  border-top:1px solid #ece8f3;
  color:#667085;
  font-size:9px;
  font-weight:900;
  letter-spacing:.06em;
  text-transform:uppercase
}
.tool-subheading.first {
  padding-top:0;
  margin-top:0;
  border-top:0
}
.grade-alignment-title {
  padding-top:8px;
  margin-top:9px;
  border-top:1px solid #ece8f3
}
.grade-control-grid {
  display:grid;
  grid-template-columns:1fr 82px;
  gap:8px
}
.grade-control-grid.three,.grade-control-grid.equal {
  grid-template-columns:1fr 1fr
}
.grade-control label {
  display:block;
  margin-bottom:5px;
  color:#344054;
  font-size:10px;
  font-weight:800
}
.grade-control .input {
  min-height:34px;
  padding:5px 7px
}
.grade-control input[type="color"] {
  width:100%;
  height:34px;
  padding:3px;
  background:#fff;
  border:1px solid #cbd5e1;
  border-radius:6px;
  cursor:pointer
}
.grade-italic {
  min-height:34px;
  padding:7px 8px;
  display:flex!important;
  align-items:center;
  gap:7px;
  margin:0!important;
  background:#f8fafc;
  border:1px solid #d8e0ea;
  border-radius:6px
}
.grade-italic input {
  margin:0
}
.grade-align-note {
  padding:7px 8px;
  margin:8px 0 0!important;
  color:#4f46e5!important;
  background:#f5f3ff;
  border-radius:6px
}
.standard-typography {
  background:#eef6ff;
  border-color:#bfd7fb
}
.standard-typography h3,.standard-typography .grade-part-title {
  color:#1748b5
}
.appearance-grid {
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:8px
}
.appearance-grid label {
  display:block;
  color:#344054;
  font-size:10px;
  font-weight:800
}
.appearance-grid input[type="color"] {
  width:100%;
  height:34px;
  margin-top:5px;
  padding:3px;
  background:#fff;
  border:1px solid #cbd5e1;
  border-radius:6px;
  cursor:pointer
}
.appearance-grid .btn {
  width:100%;
  margin-top:5px
}
.rotation-presets {
  display:grid;
  grid-template-columns:repeat(4,1fr);
  gap:6px;
  margin-bottom:8px
}
.rotation-presets .btn {
  min-height:34px;
  padding:5px
}
.class-content.grade-pair-aligned {
  grid-auto-rows:max-content;
  align-items:baseline!important
}
.class-content.grade-pair-aligned .grade-segment {
  height:auto!important;
  align-items:baseline!important
}
.element-group {
  padding:11px;
  margin-bottom:11px;
  border:1px solid #d8e2ef;
  border-radius:10px;
  background:#fff
}
.element-group:last-child {
  margin-bottom:0
}
.element-group h3 {
  margin:0 0 4px;
  color:#1f3658;
  font-size:12px
}
.element-group p {
  margin:0 0 9px;
  color:#667085;
  font-size:10px;
  line-height:1.4
}
.design-element-group {
  border-color:#b9d7cc;
  background:#f4fbf8
}
.design-element-group .element-option-grid button::before {
  background:#16825d
}
.data-element-group {
  border-color:#c9d8f3;
  background:#f5f8ff
}
.data-element-group .element-option-grid button::before {
  background:#2563eb
}
.alignment-guide {
  position:absolute;
  z-index:9999;
  display:none;
  pointer-events:none;
  filter:drop-shadow(0 0 2px #fff)
}
.alignment-guide.vertical {
  top:0;
  bottom:0;
  width:2px;
  background:repeating-linear-gradient(to bottom,#ff006e 0 8px,transparent 8px 11px)
}
.alignment-guide.horizontal {
  left:0;
  right:0;
  height:2px;
  background:repeating-linear-gradient(to right,#ff006e 0 8px,transparent 8px 11px)
}
/* Card appearance stays visible with the setup fields. */
.card-appearance-section {margin-top:16px;}

</style>

<style>
.designer-document-panel {flex:0 0 auto;background:#fff;border-bottom:1px solid #dce3ec;min-width:0;}
.designer-document-actions {display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 16px;border-bottom:1px solid #e7ecf2;flex-wrap:wrap;}
.designer-file-actions,.designer-history-actions {display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.designer-history-actions {margin-left:auto;}
.designer-document-panel .design-tabs-wrap {display:flex;align-items:center;gap:12px;padding:10px 16px;margin:0;border:0;background:#f8fafc;min-width:0;}
.designer-document-panel .design-tabs {flex:1 1 0;min-width:0;display:flex;flex-wrap:nowrap;overflow-x:auto;justify-content:flex-start;}
.designer-document-panel .design-tab {flex:0 0 auto;}
.designer-document-panel .design-tabs-label {flex:0 0 auto;margin:0;white-space:nowrap;}
.designer-history-actions .btn {min-height:38px;}
@media(max-width:600px) {.designer-document-actions {padding:10px;gap:8px;} .designer-document-panel .design-tabs-wrap {padding:10px;} .designer-document-panel .design-tabs-label {font-size:10px;}}
</style>

<style id="simplified-designer-ui">
/* All rules are scoped to the designer UI; saved card elements retain their styles. */
@media screen {
 .topbar {padding:14px 22px;border-bottom:1px solid #dde3eb;box-shadow:none;}
 .topbar h1 {font-size:20px;}
 .topbar p {font-size:12px;}
 .app {display:grid;gap:0;}
 .sidebar {scrollbar-width:thin;}
 .sidebar.left {border-right:1px solid #e0e6ee;}
 .sidebar.right {border-left:1px solid #e0e6ee;}
 .sidebar .section {padding:0 0 18px;margin:0 0 18px;border:0;border-bottom:1px solid #e4e9f0;border-radius:0;background:transparent;box-shadow:none;}
 .sidebar .section h2 {font-size:13px;text-transform:none;letter-spacing:0;color:#243247;}
 .sidebar .collapsible>summary {font-size:13px;color:#243247;padding:3px 0 12px;text-transform:none;letter-spacing:0;}
 .sidebar .panel-heading span {font-size:12px;line-height:1.5;}
 .sidebar .step-number {display:none;}
 .sidebar .input {min-height:34px;border-radius:6px;box-shadow:none;font-size:12px;}
 .sidebar .field {margin-bottom:12px;}
 .sidebar .label {color:#475569;font-size:11px;}
 .workspace {min-width:0;padding:0 0 24px;}
 .designer-document-panel {border:0;border-radius:0;box-shadow:none;}
 .designer-document-actions {padding:12px 16px;}
 .designer-document-panel .design-tabs-wrap {border-radius:0;box-shadow:none;}
 .design-tab {box-shadow:none;border-radius:6px;font-size:12px;}
 .design-tab.active {background:#fff;border-color:#93afd5;color:#194f99;}
 .canvas-toolbar {padding:10px 16px;border:0;border-bottom:1px solid #dde3eb;border-radius:0;box-shadow:none;margin:0 0 24px;}
 .side-tab {padding:6px 12px;font-size:12px;background:#f3f5f8;color:#475569;border:1px solid #dce3ec;box-shadow:none;}
 .side-tab.active {background:#e7effb;color:#194f99;border-color:#aac0df;}
 .card-shell {margin-left:auto;margin-right:auto;}
 .element-picker {padding:0;border:0;background:transparent;}
 .element-group {padding:10px 0;border:0;background:transparent;border-radius:0;}
 .element-group h3 {font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:.04em;}
 .element-group p {font-size:11px;line-height:1.5;color:#64748b;margin-bottom:10px;}
 .element-option-grid {display:grid;grid-template-columns:1fr 1fr;gap:6px;}
 .element-option-grid button {text-align:left;padding:6px 8px;background:#f8fafc;color:#334155;border:1px solid #e0e6ee;border-radius:6px;box-shadow:none;font-size:11px;}
 .element-option-grid button:hover {background:#eaf2ff;border-color:#9db7da;}
 .layers {max-height:180px;overflow:auto;}
 .layer {padding:8px;border:1px solid #e0e6ee;border-radius:6px;box-shadow:none;background:#fafbfd;}
 .layer.active {background:#eaf2ff;border-color:#9db7da;}
 .simple-details {border:1px solid #e0e6ee;border-radius:7px;background:#fff;box-shadow:none;margin-bottom:12px;}
 .simple-details summary {font-size:12px;color:#334155;background:#f8fafc;}
 .grade-color-panel {padding:12px;background:#fafbfd;border:1px solid #e4e9f0;border-radius:7px;box-shadow:none;}
 .designer-getting-started {font-size:11px;line-height:1.6;color:#64748b;margin:0 0 20px;}
 .designer-getting-started summary {cursor:pointer;color:#3b5d8b;font-weight:600;}
 .empty-state {background:#f8fafc;border:1px dashed #d5dfeb;padding:18px;font-size:12px;line-height:1.6;color:#64748b;}
 .element-search {margin-bottom:8px;}
}
@media screen and (max-width:1100px) {.app {grid-template-columns:230px minmax(260px,1fr) 280px;}}
@media screen and (max-width:850px) {.app {display:flex;flex-direction:column;height:auto;overflow:visible;}.workspace {order:0;min-height:500px;width:100%;}.sidebar {width:100%;max-height:none;overflow:visible;}.sidebar.left {order:1;}.sidebar.right {order:2;}}
</style>
<script>
function filterDesignerElements(query) {
  const term = String(query || '').trim().toLowerCase();
  let visible = 0;
  document.querySelectorAll('#newElementPicker .element-group').forEach(function(group) {
    let matches = 0;
    group.querySelectorAll('button').forEach(function(button) {
      const show = !term || button.textContent.toLowerCase().includes(term);
      button.hidden = !show;
      if (show) matches++;
    });
    group.hidden = matches === 0;
    visible += matches;
  });
  document.getElementById('elementSearchEmpty').hidden = visible > 0;
}
</script>

<style id="designer-comfort-layout">
@media screen {
  body {background:#dce2e9;}
  .topbar {background:#e6ebf1;border-color:#bdc9d7;}
  .app {grid-template-columns:340px minmax(280px,1fr) 380px;}
  .sidebar {background:#e4eaf1;padding:20px;}
  .sidebar.left,.sidebar.right {border-color:#bdc9d7;}
  .workspace {background:#cbd5e1;background-image:none;}
  .designer-document-panel,.designer-document-actions {background:#e2e8f0;}
  .designer-document-panel .design-tabs-wrap {background:#d5deea;}
  .canvas-toolbar {background:#dde5ef;border-color:#bcc9d9;}
  .sidebar .input {background:#f0f3f7;border-color:#bac8d9;color:#243247;}
  .sidebar .simple-details,.sidebar .grade-color-panel {background:#dce4ef;border-color:#bac8d9;}
  .sidebar .simple-details summary {background:#d4dfec;color:#243247;}
  .sidebar .element-option-grid button,
  .sidebar .element-option-grid button.studio-sized-tool {
    max-width:100%;
    line-height:1.35!important;
    border-color:#b8c7da;
  }
  .sidebar .layer {min-width:0;background:#eaf0f6;border-color:#bdcadb;}
  .sidebar .layer.active {background:#cbdcf2;border-color:#779bc7;}
  .sidebar .layer>* {min-width:0;overflow-wrap:anywhere;}
  .sidebar .label,.sidebar .grade-control label {white-space:normal;overflow-wrap:anywhere;}
  .sidebar .empty-state {background:#dce5ef;border-color:#b9c8db;color:#475569;}
}
@media screen and (max-width:1250px) {
  .app {grid-template-columns:300px minmax(280px,1fr) 330px;}
  .sidebar {padding:16px;}
}
@media screen and (max-width:1000px) {
  .app {display:flex;flex-direction:column;height:auto;overflow:visible;}
  .workspace {order:0;width:100%;min-height:500px;}
  .sidebar {width:100%;max-height:none;overflow:visible;}
  .sidebar.left {order:1;}
  .sidebar.right {order:2;}
}
</style>

<style id="readable-element-picker">
/* A compact list avoids squeezed labels and gives every icon a consistent column. */
@media screen {
  .sidebar .element-group {
    padding:12px 0;
    background:transparent;
    border:0;
  }
  .sidebar .element-group h3 {
    margin:0 0 5px;
    font:700 11px/1.4 "Segoe UI",Arial,sans-serif;
    color:#405571;
    letter-spacing:.06em;
  }
  .sidebar .element-group p {
    margin:0 0 10px;
    font:400 11px/1.5 "Segoe UI",Arial,sans-serif;
    color:#53677f;
  }
  .sidebar .element-option-grid {
    display:grid;
    grid-template-columns:minmax(0,1fr);
    gap:5px;
  }
  .sidebar .element-option-grid button,
  .sidebar .element-option-grid button.studio-sized-tool {
    display:flex;
    align-items:center;
    justify-content:flex-start;
    gap:0;
    width:100%;
    min-width:0;
    min-height:36px!important;
    height:auto!important;
    padding:8px 12px!important;
    margin:0;
    border:1px solid #c4cfdd;
    border-radius:6px;
    box-shadow:none;
    background:#eaf0f6;
    color:#223b59;
    font:500 12px/1.45 "Segoe UI",Arial,sans-serif!important;
    text-align:left;
    white-space:normal!important;
    overflow-wrap:break-word;
    cursor:pointer;
    transition:background .15s,border-color .15s;
  }
  .sidebar .element-option-grid button.designer-small-icon::before {
    color:#315c8c!important;
    background-color:#315c8c!important;
    opacity:1!important;
    width:16px!important;
    height:16px!important;
    flex:0 0 16px;
    margin:0 12px 0 0!important;
  }
  .sidebar .element-option-grid button:hover {
    color:#183f71;
    background:#d8e5f5;
    border-color:#91abce;
  }
  .sidebar .element-option-grid button:focus-visible {
    outline:2px solid #356aa9;
    outline-offset:2px;
  }
  .sidebar .element-option-grid button:active {background:#c9dcf3;}
}
</style>
<style>
/* Proportional desktop workspace; narrow devices retain the stacked layout. */
@media screen and (min-width:1001px) {
  .app {
    display:grid;
    grid-template-columns:minmax(0,1fr) minmax(0,3fr) minmax(0,1fr);
    gap:0;
    width:100%;
  }
  .app > .sidebar,
  .app > .workspace {
    min-width:0;
    width:auto;
    max-width:100%;
    box-sizing:border-box;
  }
  .app > .sidebar {padding:clamp(10px,1.2vw,20px);}
  .sidebar .inline {flex-wrap:wrap;}
  .sidebar .inline > .field {min-width:0;}
  .sidebar .input {max-width:100%;min-width:0;box-sizing:border-box;}
}
</style>
<style>
/* A quiet, single-column inspector with controls grouped by purpose. */
.sidebar.right .selected-element-name {margin:0 0 14px;padding:8px 10px;background:#d2dfed;border-radius:6px;font-size:13px;font-weight:700;color:#243247;}
.sidebar.right #inspector .grade-color-panel,
.sidebar.right #inspector #orientationField,
.sidebar.right #inspector .inspector-box-style,
.sidebar.right #inspector > .transport-help {margin:14px 0 0;padding:14px 0;border:0;border-top:1px solid #bdc9d7;border-radius:0;background:transparent;box-shadow:none;}
.sidebar.right #inspector h3,
.sidebar.right #inspector .format-name,
.sidebar.right #orientationField > .grade-part-title {font-size:12px;font-weight:700;text-transform:none;letter-spacing:normal;color:#243247;margin:0 0 10px;}
.sidebar.right #inspector p {font-size:11px;line-height:1.5;}
.sidebar.right .grade-part {padding:10px 0;background:transparent;border:0;}
.sidebar.right .grade-control-grid {grid-template-columns:minmax(0,1fr);}
.sidebar.right .grade-control-grid.equal,
.sidebar.right .grade-control-grid.three {grid-template-columns:repeat(2,minmax(0,1fr));}
.sidebar.right .grade-control {min-width:0;}
.sidebar.right .grade-control .input {width:100%;min-width:0;}
.sidebar.right .rotation-presets {display:grid;}
.sidebar.right .rotation-presets .btn {width:100%;min-width:0;}
.sidebar.right .inspector-content {padding:0;margin:0;}
.sidebar.right .tool-subheading {font-size:10px;text-transform:none;letter-spacing:normal;}
.sidebar.right .transport-rule {grid-template-columns:28px minmax(0,1fr);}
.sidebar.right .transport-rule strong {font-size:11px;}
.sidebar.right [hidden] {display:none!important;}
</style>
<style>
.sidebar.right .layers {max-height:180px;overflow:auto;}
.sidebar.right .inspector-tab-panel {padding:0;}
.sidebar.right #inspector .grade-color-panel,
.sidebar.right #inspector .inspector-box-style,
.sidebar.right #inspector #orientationField {border:0;margin:0;padding:0;}
.sidebar.right #standardTypography > h3,
.sidebar.right #standardTypography .tool-subheading,
.sidebar.right #standardTypography .grade-part > .grade-part-title:first-child,
.sidebar.right #classTypography > h3,
.sidebar.right #classTypography > p,
.sidebar.right .inspector-box-style .tool-subheading {display:none;}
.sidebar.right #standardTypography > p {margin:0 0 10px;color:#53657b;}
.sidebar.right .grade-control-grid {gap:8px;}
.sidebar.right #standardTypography .grade-part {padding:0 0 12px;}
.sidebar.right .grade-control label {font-size:11px!important;margin-bottom:5px;}
.sidebar.right .grade-control-grid.equal {grid-template-columns:repeat(2,minmax(0,1fr));}
.sidebar.right #classTypography details {border:1px solid #bac8d9;border-radius:6px;margin-bottom:8px;}
.sidebar.right #classTypography details > summary {cursor:pointer;font-size:12px;font-weight:600;color:#243247;}
.sidebar.right #classTypography details > .grade-part-title {display:none;}
.sidebar.right #classTypography .tool-subheading {display:none;}
.sidebar.right .inspector-tab-panel:focus {outline:none;}
.sidebar.right #selectedElementName {background:transparent;padding:0;margin:0 0 8px;font-size:13px;}
</style>
<style>
/* Compact, labeled text controls with explicit selected states. */
.sidebar.right .text-style-buttons {display:flex;flex-wrap:wrap;gap:6px;margin:10px 0;}
.sidebar.right button.format-letter,
.sidebar.right button.size-step,
.sidebar.right button.align-choice {
  display:inline-flex;align-items:center;justify-content:center;
  min-width:32px;height:32px!important;min-height:32px!important;
  padding:4px 7px!important;border:1px solid #aebed0;border-radius:5px;
  background:#f1f5f9;color:#243247;font-size:13px!important;cursor:pointer;
}
.sidebar.right button.format-letter::before,
.sidebar.right button.size-step::before,
.sidebar.right button.align-choice::before {display:none!important;}
.sidebar.right button[aria-pressed="true"].format-letter,
.sidebar.right button[aria-pressed="true"].align-choice {background:#d5e5fb;border-color:#3868a8;color:#16447e;box-shadow:inset 0 0 0 1px #3868a8;}
.sidebar.right button.format-letter:focus-visible,
.sidebar.right button.size-step:focus-visible,
.sidebar.right button.align-choice:focus-visible {outline:2px solid #185adb;outline-offset:2px;}
.sidebar.right .size-stepper {display:grid;grid-template-columns:30px minmax(0,1fr) 30px;gap:4px;align-items:center;}
.sidebar.right .size-stepper select {padding-left:5px;padding-right:3px;}
.sidebar.right .alignment-buttons {display:flex;gap:3px;}
.sidebar.right button.align-choice {flex:1;min-width:28px;font-size:10px!important;padding:4px!important;}
.sidebar.right .format-letter[data-style="italic"] {font-family:Georgia,serif;font-style:italic;}
.sidebar.right .format-letter[data-style="underline"] {text-decoration:underline;text-underline-offset:3px;}
.sidebar.right .format-letter[data-style="strike"] {text-decoration:line-through;}
.sidebar.right .compact-style-caption {font-size:11px;color:#475569;margin:10px 0 4px;}
</style>
<style>
.sidebar.right .font-style-group {
  border-radius:8px;
}
.sidebar.right .font-style-heading {
  margin:0 0 8px;
  font-size:11px;
  font-weight:700;
  color:#34465d;
}
.sidebar.right .font-style-group .font-weight-row {
  display:flex;
  flex-direction:column;
  gap:5px;
  width:100%;
}
.sidebar.right .font-style-group .font-weight-row label {margin:0;}
.sidebar.right .grade-control-grid.font-color-row {
  grid-template-columns:minmax(0,1fr);
  margin-top:8px;
}
.sidebar.right .font-color-row input[type="color"] {
  width:100%;
  height:32px;
  border:1px solid #b5c4d6;
  border-radius:5px;
  padding:3px;
  background:#f1f5f9;
  cursor:pointer;
}
</style>
<style>
.sidebar.right #standardTypography .grade-control-grid:not(.equal):not(.font-color-row),
.sidebar.right #classTypography .grade-control-grid:not(.equal):not(.three):not(.font-color-row) {grid-template-columns:minmax(0,1fr) minmax(0,1fr);}
.sidebar.right .font-style-group {padding:0;border:0;background:transparent;margin:12px 0;}
.sidebar.right .font-style-heading {display:none;}
.sidebar.right .font-style-group .text-style-buttons {display:flex;flex-wrap:wrap;gap:4px;margin:0;align-items:center;}
.sidebar.right .font-style-group .format-letter {flex:0 0 29px;min-width:29px;max-width:29px;height:32px!important;padding:3px!important;}
.sidebar.right .font-style-group .color-letter {position:relative;display:inline-flex;align-items:center;justify-content:center;width:29px;height:32px;box-sizing:border-box;background:white;border:1px solid #aebed0;border-radius:5px;font-size:15px;font-weight:700;color:#243247;cursor:pointer;}
.sidebar.right .color-letter .color-indicator {border-bottom:3px solid var(--font-ink,#111827);line-height:19px;}
.sidebar.right .color-letter input[type="color"] {position:absolute;inset:0;width:100%!important;height:100%!important;opacity:0;padding:0;cursor:pointer;}
.sidebar.right .color-letter:focus-within {outline:2px solid #185adb;outline-offset:2px;}
.sidebar.right .align-choice svg {width:20px;height:20px;display:block;pointer-events:none;}
.sidebar.right .grade-control-grid.equal:has(.alignment-buttons) {grid-template-columns:1fr;gap:8px;}
.sidebar.right .alignment-buttons {flex-wrap:nowrap;}
.sidebar.right .align-choice {max-width:48px;}
</style>
<style>
.sidebar.right .unified-alignment {margin-top:12px;}
.sidebar.right .unified-alignment > h4 {margin:0 0 8px;font-size:11px;font-weight:700;color:#34465d;}
.sidebar.right .unified-alignment .alignment-icon-row {display:flex;flex-wrap:wrap;gap:8px;align-items:center;}
.sidebar.right .unified-alignment .alignment-buttons {display:flex;gap:3px;flex:0 0 auto;}
.sidebar.right .unified-alignment .alignment-buttons + .alignment-buttons {border-left:1px solid #aebed0;padding-left:8px;}
.sidebar.right .unified-alignment button.align-choice {flex:0 0 28px;width:28px;min-width:28px;max-width:28px;padding:3px!important;}
</style>
<style>
/* Text inspector: three purposeful rows, without legacy nested spacing. */
.sidebar.right .text-editor-layout {display:flex;flex-direction:column;gap:14px;padding:2px 0;min-width:0;}
.sidebar.right .text-editor-layout > .font-picker-row {
  display:grid!important;grid-template-columns:minmax(0,1.1fr) minmax(0,1fr)!important;
  gap:8px!important;margin:0!important;
}
.sidebar.right .text-editor-layout .grade-control {min-width:0;}
.sidebar.right .text-editor-layout .grade-control > label {display:block;font-size:11px;margin:0 0 5px;font-weight:600;color:#475569;}
.sidebar.right .text-editor-layout select.input {height:34px;min-height:34px;padding:5px 6px;font-size:12px;border-radius:5px;}
.sidebar.right .text-editor-layout .size-stepper {grid-template-columns:24px minmax(0,1fr) 24px;gap:2px;}
.sidebar.right .text-editor-layout .size-step {min-width:24px;width:24px;padding:2px!important;}
.sidebar.right .text-editor-layout .font-style-group {margin:0!important;padding:0!important;border:0!important;}
.sidebar.right .text-editor-layout .text-style-buttons {
  display:grid!important;
  gap:4px!important;margin:0!important;padding:5px;background:#dce5ef;border-radius:7px;
}
.sidebar.right .text-editor-layout .text-style-buttons .format-letter,
.sidebar.right .text-editor-layout .text-style-buttons .color-letter {
  width:100%;min-width:0;max-width:none;height:33px!important;box-sizing:border-box;margin:0;
}
.sidebar.right .text-editor-layout .unified-alignment {margin:0!important;padding-top:12px;border-top:1px solid #bcc9d9;}
.sidebar.right .text-editor-layout .unified-alignment h4 {margin:0 0 7px;font-size:11px;}
.sidebar.right .text-editor-layout .alignment-icon-row {display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:7px;}
.sidebar.right .text-editor-layout .alignment-buttons {display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:3px;min-width:0;}
.sidebar.right .text-editor-layout .alignment-buttons + .alignment-buttons {padding-left:7px;}
.sidebar.right .text-editor-layout button.align-choice {min-width:0;max-width:none;width:100%;height:32px!important;}
.sidebar.right .text-editor-layout .align-choice svg {width:18px;height:18px;}
.sidebar.right #classTypography details {padding:10px;background:#e8eef5;}
.sidebar.right #classTypography details > summary {padding-bottom:8px;}
.sidebar.right #classTypography .grade-align-note {display:none;}
.sidebar.right #classTypography > button {margin-top:8px;white-space:normal;height:auto!important;}
</style>
<style>
.sidebar.right #inspector .inspector-box-style {border-top:1px solid #bcc9d9;display:flex;flex-direction:column;}
.sidebar.right .box-icon-row {display:flex;gap:6px;}
.sidebar.right .box-color-icon,.sidebar.right .box-border-icon,.sidebar.right .opacity-step {display:inline-flex;align-items:center;justify-content:center;position:relative;width:32px;min-width:32px;height:32px!important;padding:4px!important;box-sizing:border-box;background:#fff;border:1px solid #aebed0;border-radius:5px;color:#243247;cursor:pointer;}
.sidebar.right .box-color-icon {font-size:22px;}
.sidebar.right .box-color-icon input {position:absolute;inset:0;opacity:0;width:100%;height:100%;cursor:pointer;}
.sidebar.right .box-border-icon::before,.sidebar.right .opacity-step::before {display:none!important;}
.sidebar.right .box-border-icon[aria-pressed="true"] {background:#d5e5fb;border-color:#3868a8;}
.sidebar.right .box-color-icon:focus-within,.sidebar.right .box-border-icon:focus-visible,.sidebar.right .opacity-step:focus-visible {outline:2px solid #185adb;outline-offset:2px;}
.sidebar.right .inspector-box-style .opacity-tool {display:grid;grid-template-columns:28px minmax(0,1fr) 28px;gap:5px;align-items:center;width:100%;}
.sidebar.right .opacity-step {width:28px;min-width:28px;}
.sidebar.right #toolbarOpacity {width:100%;min-width:0;}
.sidebar.right #toolbarOpacityValue {grid-column:1 / -1;text-align:right;font-size:11px;}
</style>
<style>
.sidebar.right .rotation-presets {grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;}
.sidebar.right .rotation-presets .rotation-letter-button {display:flex;align-items:center;justify-content:center;height:42px!important;min-height:42px!important;padding:6px!important;overflow:hidden;background:#f1f5f9;border:1px solid #aebed0;border-radius:6px;color:#243247;}
.sidebar.right .rotation-letter-button::before {display:none!important;}
.sidebar.right .rotation-letter {display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;font-family:Arial,sans-serif;font-size:21px;font-weight:700;line-height:1;transform-origin:center;}
.sidebar.right .rotation-presets .rotation-letter-button[aria-pressed="true"] {background:#d5e5fb;border-color:#3868a8;box-shadow:inset 0 0 0 1px #3868a8;color:#16447e;}
.sidebar.right .rotation-letter-button:focus-visible {outline:2px solid #185adb;outline-offset:2px;}
</style>
<style>
.sidebar.right #inspector #orientationField {
  display:flex;align-items:center;gap:7px;border-top:1px solid #bcc9d9;
}
.sidebar.right #orientationField .rotation-presets {
  display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:3px;flex:1;min-width:0;margin:0;
}
.sidebar.right #orientationField .rotation-letter-button {
  width:100%;min-width:0;height:30px!important;min-height:30px!important;padding:3px!important;
}
.sidebar.right #orientationField .rotation-letter {font-size:16px;width:20px;height:20px;}
.sidebar.right #orientationField > .grade-control {flex:0 0 62px;min-width:0;position:relative;margin:0;}
.sidebar.right #orientation {width:100%;height:30px;min-height:30px;padding:4px;font-size:12px;box-sizing:border-box;}
</style>
<style>
/* Stable element list and a single, uncluttered toolbar surface. */
.sidebar.right #layers {
  height:234px;min-height:234px;max-height:234px;
  display:flex;flex-direction:column;gap:6px;
  overflow-y:auto;overflow-x:hidden;scrollbar-gutter:stable;
  padding:0;box-sizing:border-box;
}
.sidebar.right #layers > .layer {
  height:42px;min-height:42px;flex:0 0 42px;
  box-sizing:border-box;align-items:center;margin:0;padding:6px 8px;
}
.sidebar.right #layers > .layer > span {min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.sidebar.right #selectedElementName {display:none;}
.sidebar.right .section > h2 {font-size:13px;font-weight:700;color:#243247;text-transform:none;letter-spacing:0;margin-bottom:12px;}
.sidebar.right #inspector {padding:12px;background:#edf2f7;border:1px solid #bfcbd9;border-radius:9px;}
.sidebar.right #inspector .text-editor-layout {gap:12px;}
.sidebar.right #inspector .text-style-buttons {background:transparent;padding:0;gap:4px;}
.sidebar.right #inspector .unified-alignment {padding-top:12px;}
.sidebar.right #inspector .unified-alignment h4 {font-size:11px;margin-bottom:8px;}
.sidebar.right #inspector .inspector-box-style {gap:8px;padding-top:12px;margin-top:12px;}
.sidebar.right #inspector .box-icon-row {gap:6px;}
.sidebar.right #inspector .rotation-letter-button,
.sidebar.right #inspector .format-letter,
.sidebar.right #inspector .align-choice,
.sidebar.right #inspector .box-border-icon,
.sidebar.right #inspector .opacity-step {box-shadow:none;border-radius:5px;}
.sidebar.right #inspector #orientationField {padding-top:12px;margin-top:12px;}
.sidebar.right #inspector #elementContentSettings:not([hidden]),
.sidebar.right #inspector #transportRules:not([hidden]) {margin:0 0 12px;padding:0 0 12px;border:0;border-bottom:1px solid #bcc9d9;background:transparent;}
.sidebar.right #inspector #classTypography details {background:transparent;padding:8px;}
.sidebar.right #noSelection {padding:16px 12px;font-size:12px;line-height:1.5;}
</style>
<style>
.sidebar.right .colors-border-group {margin:14px 0 0;padding:12px 0;border-top:1px solid #bcc9d9;}
.sidebar.right .colors-border-group h4 {font-size:11px;font-weight:700;color:#34465d;margin:0 0 10px;}
.sidebar.right .color-setting-row {display:flex;align-items:center;justify-content:space-between;gap:8px;margin:0 0 8px;min-height:32px;}
.sidebar.right .color-setting-row > label {font-size:11px;font-weight:600;color:#34465d;}
.sidebar.right .color-setting-row input[type="color"] {position:static;opacity:1;width:58px!important;height:30px!important;min-height:30px;border:1px solid #9baec4;border-radius:5px;background:#fff;padding:3px;cursor:pointer;box-sizing:border-box;}
.sidebar.right .color-setting-row .box-border-icon {gap:6px;font-size:11px;}
.sidebar.right .color-setting-row .box-border-icon::before {display:none!important;}
.sidebar.right .text-editor-layout .text-style-buttons {grid-template-columns:repeat(5,minmax(0,1fr));}
.sidebar.right #classTypography .text-editor-layout .text-style-buttons {display:flex!important;}
.sidebar.right #classTypography .text-editor-layout .text-style-buttons .format-letter {width:32px;flex:0 0 32px;}
</style>
<style>
.sidebar.right .color-setting-row .box-border-icon {width:34px;min-width:34px;}
.sidebar.right .color-setting-row .border-thickness {width:78px;min-width:0;height:32px;min-height:32px;padding:4px 6px;font-size:12px;}
</style>
<style>
.sidebar.right .border-line-picker {position:relative;width:90px;border:0!important;padding:0!important;margin:0!important;background:transparent!important;}
.sidebar.right .border-line-picker > summary {display:flex;align-items:center;justify-content:space-between;gap:8px;height:32px;padding:5px 8px!important;box-sizing:border-box;border:1px solid #aebed0;border-radius:5px;background:#f1f5f9;cursor:pointer;list-style:none;}
.sidebar.right .border-line-picker > summary::-webkit-details-marker {display:none;}
.sidebar.right .border-line-picker > summary::after {content:'▾';font-size:11px;color:#34465d;}
.sidebar.right .border-line-sample {display:block;width:48px;max-width:100%;background:#243247;flex-shrink:0;}
.sidebar.right .border-line-options {position:absolute;right:0;top:36px;z-index:50;width:112px;max-height:240px;overflow:auto;padding:5px;background:#fff;border:1px solid #aebed0;border-radius:6px;box-shadow:0 5px 16px #24324726;}
.sidebar.right .border-line-option {display:flex;align-items:center;justify-content:center;width:100%;height:30px!important;min-height:30px!important;padding:4px!important;margin:0 0 2px;background:#fff;border:1px solid transparent;border-radius:4px;cursor:pointer;}
.sidebar.right .border-line-option::before {display:none!important;}
.sidebar.right .border-line-option:hover {background:#edf3fb;}
.sidebar.right .border-line-option[aria-pressed="true"] {background:#d5e5fb;border-color:#3868a8;}
.sidebar.right .border-line-option:focus-visible,.sidebar.right .border-line-picker > summary:focus-visible {outline:2px solid #185adb;outline-offset:1px;}
</style>
<style>
.sidebar.right .text-editor-layout .font-size-input {width:100%;min-width:0;height:34px;min-height:34px;padding:4px;font-size:12px;border-radius:5px;box-sizing:border-box;}
</style>
<style>
.sidebar.right .font-size-combo {position:relative;min-width:0;display:flex;}
.sidebar.right .font-size-combo .font-size-input {padding-right:16px;appearance:textfield;-moz-appearance:textfield;}
.sidebar.right .font-size-combo input::-webkit-inner-spin-button {appearance:none;}
.sidebar.right .font-size-open {position:absolute;right:1px;top:1px;bottom:1px;width:16px;min-width:0;height:auto!important;padding:0!important;border:0;background:transparent;color:#34465d;cursor:pointer;font-size:11px!important;}
.sidebar.right .font-size-open::before {display:none!important;}
.sidebar.right .font-size-options {position:absolute;top:36px;right:0;z-index:100;width:80px;max-height:220px;overflow:auto;padding:4px;border:1px solid #aebed0;border-radius:5px;background:#fff;box-shadow:0 4px 12px #0002;}
.sidebar.right .font-size-choice {display:block;width:100%;height:28px!important;min-height:28px!important;padding:3px 8px!important;border:0;border-radius:3px;background:#fff;color:#243247;text-align:left;font-size:12px!important;cursor:pointer;}
.sidebar.right .font-size-choice::before {display:none!important;}
.sidebar.right .font-size-choice:hover,.sidebar.right .font-size-choice:focus-visible {background:#d5e5fb;}
</style>
</head>
<body>
<header class="topbar">
<div class="topbar-main">
<div class="brand">
<div class="mark" role="img" aria-label="Design">
<svg viewBox="0 0 48 48" aria-hidden="true">
<path d="M24 7C13 7 6 14.5 6 24s7.7 17 17 17h3c2.2 0 3.2-2.7 1.6-4.2-1.3-1.2-.5-3.4 1.3-3.4h5.6c5 0 7.5-3.7 7.5-8.4C42 14.7 34.2 7 24 7z" fill="#fff4d6"/>
<circle cx="15" cy="20" r="3" fill="#ff5c70"/>
<circle cx="22" cy="14" r="3" fill="#ffd34e"/>
<circle cx="30" cy="16" r="3" fill="#38d0b4"/>
<circle cx="34" cy="24" r="3" fill="#5b8cff"/>
<path d="M17 38l15-18 5 4-15 18-6 1 1-5z" fill="#7141c6"/>
<path d="M32 20l5 4" stroke="#fff" stroke-width="2"/>
</svg>
</div>
<div>
<h1>ID Card Design Studio</h1>
<p>Create the visual layout first. Map data columns later in the Card Studio.</p>
</div>
</div>
<div class="actions">
<a class="btn home" href="<?!= webAppUrl ?>" target="_top">← ID Card Studio</a>
</div>
</div>
<input id="openDesignFile" type="file" accept=".json,application/json" hidden onchange="openDesignFromLocalAlbum(event)">

<p id="saveStatus" class="status header-status">
</p>
</header>
<main class="app">
<aside class="sidebar left">
<div class="panel-heading">
<strong>Card Setup &amp; Elements</strong>
<span>Choose a format and add what you need.</span>
</div>
<details class="designer-getting-started"><summary>How to create a card</summary><p>Choose a card format, then add elements. Select an element on the card to edit it. Save the design and open it in a Card Studio to connect your data.</p></details>
<details class="section collapsible" open>
<summary>
<span class="step-title">
<span class="step-number">1</span> Card Setup</span>
</summary>
<div class="section-body">
<div class="field">
<label class="label">Design Name</label>
<input id="designName" class="input" value="New ID Card">
</div>
<div class="field">
<label class="label">Card Type</label>
<select id="cardType" class="input" onchange="changeCardType()">
<option value="portrait-hole">CR80 Portrait (Lanyard Hole) - 2.125 x 3.375 in.</option>
<option value="landscape-hole">CR80 Landscape (Lanyard Hole) - 3.375 x 2.125 in.</option>
<option value="portrait-plain">CR80 Portrait (No Hole) - 2.125 x 3.375 in.</option>
<option value="landscape-plain">CR80 Landscape (No Hole) - 3.375 x 2.125 in.</option>
</select>
</div>
<section class="card-appearance-section" aria-labelledby="cardAppearanceHeading">
<div id="cardAppearanceHeading" class="label">Card Appearance</div>
<div class="simple-details-body">
<div class="inline">
<div class="field">
<label class="label">Background</label>
<input id="cardColor" class="input" type="color" value="#ffffff" oninput="updateCardStyle()">
</div>
<div class="field">
<label class="label">Border</label>
<input id="borderColor" class="input" type="color" value="#98a2b3" oninput="updateCardStyle()">
</div>
</div>
<div class="field">
<label class="label">Corner Radius <span id="cornerValue">12px</span>
</label>
<input id="cornerRadius" class="input" type="range" min="0" max="24" value="12" oninput="updateCardStyle()">
</div>
</div>
</section>
</div>
</details>
<details class="section collapsible" open>
<summary>
<span class="step-title">
<span class="step-number">2</span> Add Elements</span>
</summary>
<div class="section-body">
<input class="input element-search" type="search" placeholder="Find an element…" aria-label="Find an element" oninput="filterDesignerElements(this.value)">
<p id="elementSearchEmpty" class="hint" hidden>No matching elements.</p>
<div id="newElementPicker" class="element-picker">
<section class="element-group design-element-group">
<h3>Design Elements</h3>
<p>Artwork, school year, and photo frame.</p>
<div id="designElementOptions" class="element-option-grid">
</div>
</section>
<section class="element-group data-element-group">
<h3>Data Elements</h3>
<p>Connect these fields to spreadsheet columns in a Card Studio.</p>
<div id="dataElementOptions" class="element-option-grid">
</div>
</section>
</div>
<input id="designLogoInput" type="file" accept="image/*" hidden onchange="finishLogoUpload(event)">
<input id="signatureImageInput" type="file" accept="image/*" hidden onchange="finishSignatureUpload(event)">
<input id="designImageInput" type="file" accept="image/*" hidden onchange="finishImageUpload(event)">
<p class="hint">Drag to move. Pull an edge to resize. Use the round handle to rotate.</p>
</div>
</details>
</aside>
<section class="workspace">
<div class="designer-document-panel">
<div class="designer-document-actions">
<div class="designer-file-actions" aria-label="Design file actions">
<button class="btn primary" onclick="newCard()" title="Create an empty design in a new preview tab.">New Card</button>
<button class="btn" onclick="chooseDesignFile()" title="Open a saved .json design file from your device in a new tab.">Open</button>
<button class="btn" onclick="saveDesignToLocalAlbum()" title="Save both card sides to a .json file on your device. Choose the folder and filename.">Save</button>
</div>
<div id="designHistoryActions" class="designer-history-actions" aria-label="Undo and redo"></div>
</div>
<div class="design-tabs-wrap">
<div id="designTabs" class="design-tabs" role="tablist" aria-label="Open card designs"></div>
<span class="design-tabs-label">Open Cards</span>
</div>
</div>
<div class="canvas-toolbar">
<div class="workspace-head">
<strong id="workspaceTitle" hidden>New ID Card</strong>
<span id="sizeLabel">
</span>
</div>
<div class="side-tabs" aria-label="Card side">
<button id="frontSideTab" class="side-tab active" type="button" onclick="switchCardSide('front')">Front Side</button>
<button id="backSideTab" class="side-tab" type="button" onclick="switchCardSide('back')">Back Side</button>
</div>
</div>
<div class="card-shell">
<div id="designCard" class="design-card" onclick="clearSelection(event)">
<div id="verticalGuide" class="alignment-guide vertical">
</div>
<div id="horizontalGuide" class="alignment-guide horizontal">
</div>
<div id="lanyard" class="lanyard">
</div>
</div>
</div>
</section>
<aside class="sidebar right">
<section class="section element-list-section">
<h2>Element List</h2>
<div class="section-body">

<div id="layers" class="layers">
<div class="empty-state">No elements yet</div>
</div>
</div>
</section>
<section class="section">
<h2>Toolbar</h2>
<div id="noSelection" class="empty-state">Select an element on the card or from the list above to edit its settings.</div>
<div id="inspector" hidden>
<p id="selectedElementName" class="selected-element-name"></p>
<div id="elementContentSettings" class="inspector-content">
<div class="simple-details-body">
<div id="editableElementContent" class="field">
<label id="elementFieldLabel" class="label">Element Name</label>
<textarea id="elementField" class="input" rows="1" style="resize:vertical;white-space:pre-wrap" oninput="updateSelectedFromInspector()" disabled></textarea>
</div>
<div id="signatureTools" hidden><button class="btn" type="button" onclick="chooseSignature(true)">Replace Signature</button><p class="hint">Upload signature artwork. A transparent PNG works well.</p></div>
<div id="symbolTools" hidden><label class="label" for="symbolChoice">Choose a symbol</label><select id="symbolChoice" class="input" onchange="setSelectedSymbol(this.value)"><option value="★">★ Star</option><option value="☎">☎ Telephone</option><option value="✉">✉ Envelope</option><option value="⌂">⌂ Building</option><option value="●">● Circle</option><option value="✓">✓ Check</option><option value="→">→ Arrow</option><option value="ℹ">ℹ Information</option></select><p class="hint">Or enter your own symbol in the field above. Use the text tools for size and color.</p></div>
<div id="elementColumnField" hidden>
<select id="elementColumn" disabled>
<option value="">Mapped later in Card Studio</option>
</select>
</div>
</div>
</div>
<div id="transportRules" class="transport-help" hidden>
<h3>Transportation Display Rules</h3>
<p class="transport-help-intro">Enter every spreadsheet value that should display each icon, separated by commas. You will choose the Transportation column later in the Card Studio.</p>
<div class="transport-rule">
<span class="transport-rule-icon transport-emoji" role="img" aria-label="School bus">🚌</span>
<div>
<strong>Bus — shows the bus icon</strong>
<input id="transportBusValues" class="input" aria-label="Bus values" oninput="updateSelectedFromInspector()">
</div>
</div>
<div class="transport-rule">
<span class="transport-rule-icon">
<svg viewBox="0 0 24 24" fill="#27ae60" aria-hidden="true">
<circle cx="12" cy="3.5" r="2"/>
<path d="M10.2 7.1c.8-.7 2.8-.7 3.6 0l1.6 1.7c.8.8 1.8 1.3 3 1.4l-.2 2c-1.7-.1-3.2-.8-4.4-2l-.3-.3-.5 3 2.3 2.4V22h-2.2v-5.7l-2-1.9-1 3.2L7.7 22H5.2l2.9-5.4 1.1-5.8-1.4 1.4c-.8.8-1.8 1.3-2.9 1.5l-.4-2c.8-.2 1.4-.5 2-1.1l3.7-3.5z"/>
</svg>
</span>
<div>
<strong>Walking — shows the walking icon</strong>
<input id="transportWalkValues" class="input" aria-label="Walking values" oninput="updateSelectedFromInspector()">
</div>
</div>
<div class="transport-rule">
<span class="transport-rule-icon transport-emoji" role="img" aria-label="Car">🚗</span>
<div>
<strong>Pick Up — shows the car icon</strong>
<input id="transportPickupValues" class="input" aria-label="Pick Up values" oninput="updateSelectedFromInspector()">
</div>
</div>
<div class="transport-rule">
<span class="transport-rule-icon transport-none-icon">—</span>
<div>
<strong>None — displays nothing on the ID card</strong>
<input id="transportNoneValues" class="input" aria-label="None values" oninput="updateSelectedFromInspector()">
</div>
</div>
<p class="transport-help-note">Examples: “Bus, School Bus” or “Pick Up, Car Rider, Parent Pickup”. Matching ignores letter case. Blank, None, and unrecognized values show no icon.</p>
</div>
<div class="inspector-tools">
<div class="simple-details-body">
<div id="fontFamilyField" class="field" hidden>
<label class="label">Font Family</label>
<select id="fontFamily" class="input">
<option value="Segoe UI, Arial, sans-serif">Segoe UI</option>
<option value="Arial, sans-serif">Arial</option>
<option value="Georgia, serif">Georgia</option>
<option value="'Times New Roman', serif">Times New Roman</option>
<option value="Impact, sans-serif">Impact</option>
<option value="'Courier New', monospace">Courier New</option>
</select>
</div>
<div id="standardTypography" class="grade-color-panel standard-typography" hidden>
<h3 id="standardTypographyTitle">Text Style</h3>

<div class="grade-part">
<span class="grade-part-title">Typography</span>
<div class="grade-control-grid">
<div class="grade-control">
<label for="standardFont">Font Family</label>
<select id="standardFont" class="input" onchange="updateSelectedFromInspector()">
<option value="Segoe UI, Arial, sans-serif">Segoe UI</option>
<option value="Arial, sans-serif">Arial</option>
<option value="Georgia, serif">Georgia</option>
<option value="'Times New Roman', serif">Times New Roman</option>
<option value="Impact, sans-serif">Impact</option>
<option value="'Courier New', monospace">Courier New</option>
</select>
</div>
<div class="grade-control">
<label for="standardSize">Font Size</label>
<input id="standardSize" class="input font-size-input" type="number" min="1" max="72" step="1" value="12" onchange="updateSelectedFromInspector()" onkeydown="if(event.key==='Enter'){event.preventDefault();updateSelectedFromInspector();}">
</div>
</div>

<span class="tool-subheading">Font Style</span>
<div class="grade-control-grid equal" style="margin-top:8px">
<div class="grade-control">
<label for="standardColor">Font Color</label>
<input id="standardColor" type="color" value="#111827" oninput="updateSelectedFromInspector()">
</div>
<div class="grade-control">
<label for="standardWeight">Font Weight</label>
<select id="standardWeight" class="input" onchange="updateSelectedFromInspector()">
<option value="400">Normal</option>
<option value="700">Bold</option>
<option value="900">Extra Bold</option>
</select>
</div>
</div>
<div class="grade-control-grid equal" style="margin-top:8px">
<label class="grade-italic">
<input id="standardItalic" type="checkbox" onchange="updateSelectedFromInspector()"> Italic</label>
<label class="grade-italic">
<input id="standardUnderline" type="checkbox" onchange="updateSelectedFromInspector()"> Underline</label>
</div>
<label class="grade-italic" style="margin-top:8px!important">
<input id="standardStrike" type="checkbox" onchange="updateSelectedFromInspector()"> Strikethrough</label>
</div>
<div class="grade-part">
<span class="grade-part-title">Alignment</span>
<div class="grade-control-grid equal">
<div class="grade-control">
<label for="standardHorizontalAlign">Horizontal</label>
<select id="standardHorizontalAlign" class="input" onchange="updateSelectedFromInspector()">
<option value="left">Left</option>
<option value="center">Center</option>
<option value="right">Right</option>

</select>
</div>
<div class="grade-control">
<label for="standardVerticalAlign">Vertical</label>
<select id="standardVerticalAlign" class="input" onchange="updateSelectedFromInspector()">
<option value="flex-start">Top</option>
<option value="center">Center</option>
<option value="flex-end">Bottom</option>
</select>
</div>
</div>
</div>
</div>
<div id="classTypography" class="grade-color-panel" hidden>
<h3>Grade Level Label &amp; Number</h3>
<p>Set the font, color, size, and alignment of the “Grade” label and grade number separately.</p>
<div class="grade-part">
<span class="grade-part-title">“Grade” Label</span>
<span class="tool-subheading first">Typography</span>
<div class="grade-control-grid">
<div class="grade-control">
<label for="classLabelFont">Font Family</label>
<select id="classLabelFont" class="input" onchange="updateSelectedFromInspector()">
<option value="Segoe UI, Arial, sans-serif">Segoe UI</option>
<option value="Arial, sans-serif">Arial</option>
<option value="Georgia, serif">Georgia</option>
<option value="'Times New Roman', serif">Times New Roman</option>
<option value="Impact, sans-serif">Impact</option>
<option value="'Courier New', monospace">Courier New</option>
</select>
</div>
<div class="grade-control">
<label for="classLabelSize">Font Size</label>
<input id="classLabelSize" class="input font-size-input" type="number" min="1" max="72" step="1" value="12" onchange="updateSelectedFromInspector()" onkeydown="if(event.key==='Enter'){event.preventDefault();updateSelectedFromInspector();}">
</div>
</div>

<span class="tool-subheading">Font Style</span>
<div class="grade-control-grid three" style="margin-top:8px">
<div class="grade-control">
<label for="classLabelColor">Font Color</label>
<input id="classLabelColor" type="color" value="#185adb" oninput="updateSelectedFromInspector()">
</div>
<div class="grade-control">
<label for="classLabelWeight">Font Weight</label>
<select id="classLabelWeight" class="input" onchange="updateSelectedFromInspector()">
<option value="400">Normal</option>
<option value="700">Bold</option>
<option value="900">Extra Bold</option>
</select>
</div>
</div>
<label class="grade-italic" style="margin-top:8px!important">
<input id="classLabelItalic" type="checkbox" onchange="updateSelectedFromInspector()"> Italic label</label>
<span class="grade-part-title grade-alignment-title">Alignment</span>
<div class="grade-control-grid equal" style="margin-top:8px">
<div class="grade-control">
<label for="classLabelAlign">Horizontal</label>
<select id="classLabelAlign" class="input" onchange="updateSelectedFromInspector()">
<option value="flex-start">Left</option>
<option value="center">Center</option>
<option value="flex-end">Right</option>
</select>
</div>
<div class="grade-control">
<label for="classLabelVerticalAlign">Vertical</label>
<select id="classLabelVerticalAlign" class="input" onchange="updateSelectedFromInspector()">
<option value="flex-start">Top</option>
<option value="center">Center</option>
<option value="flex-end">Bottom</option>
</select>
</div>
</div>
</div>
<div class="grade-part">
<span class="grade-part-title">Grade Level Number</span>
<span class="tool-subheading first">Typography</span>
<div class="grade-control-grid">
<div class="grade-control">
<label for="classValueFont">Font Family</label>
<select id="classValueFont" class="input" onchange="updateSelectedFromInspector()">
<option value="Segoe UI, Arial, sans-serif">Segoe UI</option>
<option value="Arial, sans-serif">Arial</option>
<option value="Georgia, serif">Georgia</option>
<option value="'Times New Roman', serif">Times New Roman</option>
<option value="Impact, sans-serif">Impact</option>
<option value="'Courier New', monospace">Courier New</option>
</select>
</div>
<div class="grade-control">
<label for="classValueSize">Font Size</label>
<input id="classValueSize" class="input font-size-input" type="number" min="1" max="72" step="1" value="12" onchange="updateSelectedFromInspector()" onkeydown="if(event.key==='Enter'){event.preventDefault();updateSelectedFromInspector();}">
</div>
</div>

<span class="tool-subheading">Font Style</span>
<div class="grade-control-grid three" style="margin-top:8px">
<div class="grade-control">
<label for="classValueColor">Font Color</label>
<input id="classValueColor" type="color" value="#111827" oninput="updateSelectedFromInspector()">
</div>
<div class="grade-control">
<label for="classValueWeight">Font Weight</label>
<select id="classValueWeight" class="input" onchange="updateSelectedFromInspector()">
<option value="400">Normal</option>
<option value="700">Bold</option>
<option value="900">Extra Bold</option>
</select>
</div>
</div>
<label class="grade-italic" style="margin-top:8px!important">
<input id="classValueItalic" type="checkbox" onchange="updateSelectedFromInspector()"> Italic number</label>
<span class="grade-part-title grade-alignment-title">Alignment</span>
<div class="grade-control-grid equal" style="margin-top:8px">
<div class="grade-control">
<label for="classValueAlign">Horizontal</label>
<select id="classValueAlign" class="input" onchange="updateSelectedFromInspector()">
<option value="flex-start">Left</option>
<option value="center">Center</option>
<option value="flex-end">Right</option>
</select>
</div>
<div class="grade-control">
<label for="classValueVerticalAlign">Vertical</label>
<select id="classValueVerticalAlign" class="input" onchange="updateSelectedFromInspector()">
<option value="flex-start">Top</option>
<option value="center">Center</option>
<option value="flex-end">Bottom</option>
</select>
</div>
</div>
</div>

<p class="grade-align-note">The label and number alignment settings are saved independently with this Grade Level element.</p>
</div>
<div class="format-toolbar clear-tools inspector-box-style" aria-label="Element appearance tools">
<div class="format-control">

<div class="box-icon-row">
<label class="box-color-icon" title="Box color"><span aria-hidden="true">▰</span><input id="toolbarFillColor" type="color" aria-label="Box color" onchange="setSelectedToolbarColor('backgroundColor',this.value)"></label>
<button id="toolbarBorder" class="box-border-icon" type="button" title="Show or hide border" aria-label="Show or hide border" aria-pressed="false" onclick="toggleSelectedBorder()"><svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"/></svg></button>
</div>
</div>
<span class="format-name">Opacity</span>
<div class="opacity-tool">
<button class="opacity-step" type="button" aria-label="Decrease opacity" title="Decrease opacity" onclick="stepBoxOpacity(-5)">−</button>
<input id="toolbarOpacity" type="range" min="10" max="100" value="100" oninput="setSelectedOpacity(this.value)">
<button class="opacity-step" type="button" aria-label="Increase opacity" title="Increase opacity" onclick="stepBoxOpacity(5)">+</button>
<span id="toolbarOpacityValue">100%</span>
</div>
</div>
</div>
<div id="orientationField" class="grade-part">

<div class="rotation-presets">
<button class="btn rotation-letter-button" type="button" data-rotation="-90" title="Rotate to −90°" aria-label="Rotate to −90°" aria-pressed="false" onclick="setSelectedRotation(-90)"><span class="rotation-letter" aria-hidden="true" style="transform:rotate(-90deg)">A</span></button>
<button class="btn rotation-letter-button" type="button" data-rotation="0" title="Rotate to 0°" aria-label="Rotate to 0°" aria-pressed="false" onclick="setSelectedRotation(0)"><span class="rotation-letter" aria-hidden="true" style="transform:rotate(0deg)">A</span></button>
<button class="btn rotation-letter-button" type="button" data-rotation="90" title="Rotate to 90°" aria-label="Rotate to 90°" aria-pressed="false" onclick="setSelectedRotation(90)"><span class="rotation-letter" aria-hidden="true" style="transform:rotate(90deg)">A</span></button>
<button class="btn rotation-letter-button" type="button" data-rotation="180" title="Rotate to 180°" aria-label="Rotate to 180°" aria-pressed="false" onclick="setSelectedRotation(180)"><span class="rotation-letter" aria-hidden="true" style="transform:rotate(180deg)">A</span></button>
</div>
<div class="grade-control">

<input id="orientation" class="input" aria-label="Rotation angle in degrees" title="Enter an angle from −180 to 180 degrees" type="number" min="-180" max="180" step="1" value="0" onchange="setSelectedRotation(this.value)">
</div>
</div>
</div>
<div hidden aria-hidden="true">
<input id="rotationSlider" value="0">
<input id="posX">
<input id="posY">
<input id="elementWidth">
<input id="elementHeight">
</div>
</div>
</section>

</aside>
</main>
<script>
const STORAGE_KEY = 'id_blank_card_designs_v2';
const TYPOGRAPHY_DEFAULTS_VERSION = 1;
const FONT_SIZE_MIN = 1;
const FONT_SIZE_MAX = 72;
const CARD_TYPES = {
  'portrait-hole': {
    width: 204,
    height: 324,
    hole: true,
    label: 'CR80 Portrait (Lanyard Hole) - 2.125 x 3.375 in.'
  },
  'landscape-hole': {
    width: 324,
    height: 204,
    hole: true,
    label: 'CR80 Landscape (Lanyard Hole) - 3.375 x 2.125 in.'
  },
  'portrait-plain': {
    width: 204,
    height: 324,
    hole: false,
    label: 'CR80 Portrait (No Hole) - 2.125 x 3.375 in.'
  },
  'landscape-plain': {
    width: 324,
    height: 204,
    hole: false,
    label: 'CR80 Landscape (No Hole) - 3.375 x 2.125 in.'
  }
};
const DEFAULTS = {
  text: {
    w: 150,
    h: 28,
    fontSize: 12
  },
  image: {
    w: 140,
    h: 100
  },
  logo: {
    w: 170,
    h: 62
  },
  photo: {
    w: 118,
    h: 142
  },
  firstName: {
    w: 170,
    h: 28,
    fontSize: 12,
    fontWeight: '900'
  },
  lastName: {
    w: 170,
    h: 28,
    fontSize: 12,
    fontWeight: '900'
  },
  fullName: {
    w: 180,
    h: 30,
    fontSize: 12,
    fontWeight: '900'
  },
  schoolYear: {
    text: '',
    w: 125,
    h: 25,
    fontSize: 12,
    fontWeight: '700',
    color: '#185adb'
  },
  idNumber: {
    w: 145,
    h: 25,
    fontSize: 12,
    fontWeight: '700'
  },
  barcodeNumber: {
    w: 170,
    h: 50
  },
  qrCode: {
    w: 82,
    h: 82
  },
  title: {
    w: 160,
    h: 25,
    fontSize: 12,
    fontWeight: '700',
    color: '#d92d20'
  },
  class: {
    w: 120,
    h: 28
  },
  transportation: {
    w: 38,
    h: 38
  },
  middleName: {
    w: 160,
    h: 25,
    fontSize: 12
  },
  department: {
    w: 170,
    h: 25,
    fontSize: 12
  },
  email: {
    w: 185,
    h: 24,
    fontSize: 12
  },
  phone: {
    w: 160,
    h: 24,
    fontSize: 12
  },
  address: {
    w: 185,
    h: 34,
    fontSize: 12
  },
  dateOfBirth: {
    w: 150,
    h: 24,
    fontSize: 12
  },
  issueDate: {
    w: 150,
    h: 24,
    fontSize: 12
  },
  expirationDate: {
    w: 160,
    h: 24,
    fontSize: 12
  },
  emergencyContact: {
    w: 185,
    h: 28,
    fontSize: 12
  },
  bloodType: {
    w: 120,
    h: 24,
    fontSize: 12,
    fontWeight: '700'
  },
  campus: {
    w: 160,
    h: 25,
    fontSize: 12,
    fontWeight: '700'
  }
};
Object.assign(DEFAULTS, {
  emergencyPhone: {w:160, h:24, fontSize:12},
  homeroom: {w:150, h:24, fontSize:12},
  teacherName: {w:170, h:24, fontSize:12},
  buildingRoom: {w:160, h:24, fontSize:12},
  signature: {w:130, h:45},
  instructions: {w:180, h:70, fontSize:12, text:'If found, please return this card to the school office.'},
  divider: {w:170, h:2, backgroundColor:'#334155'},
  rectangle: {w:160, h:55, backgroundColor:'#dbe7f7'},
  circle: {w:55, h:55, backgroundColor:'#dbe7f7'},
  icon: {w:32, h:32, fontSize:24, text:'★'}
});
const LABELS = {
  emergencyPhone: 'Emergency Phone',
  homeroom: 'Homeroom / Advisory',
  teacherName: 'Teacher Name',
  buildingRoom: 'Building / Room',
  signature: 'Signature',
  instructions: 'Instructions / Rules',
  divider: 'Line / Divider',
  rectangle: 'Rectangle',
  circle: 'Circle',
  icon: 'Icon / Symbol',
  text: 'Text',
  image: 'Image',
  logo: 'Logo',
  photo: 'Photo Frame',
  firstName: 'First Name',
  lastName: 'Last Name',
  fullName: 'Full Name',
  schoolYear: 'School Year',
  idNumber: 'ID Number',
  barcodeNumber: 'Barcode Number',
  qrCode: 'QR Code',
  title: 'Title',
  class: 'Grade Level',
  transportation: 'Transportation',
  middleName: 'Middle Name',
  department: 'Department',
  email: 'E-Mail',
  phone: 'Phone Number',
  address: 'Address',
  dateOfBirth: 'Date of Birth',
  issueDate: 'Issue Date',
  expirationDate: 'Expiration Date',
  emergencyContact: 'Emergency Contact',
  bloodType: 'Blood Type',
  campus: 'Campus Name'
};
const DESIGN_ELEMENT_ORDER = ['image', 'logo', 'schoolYear', 'photo', 'signature', 'instructions', 'divider', 'rectangle', 'circle', 'icon'].sort(function (a, b) {
  return LABELS[a].localeCompare(LABELS[b]);
});
const DATA_ELEMENT_ORDER = ['emergencyPhone', 'homeroom', 'teacherName', 'buildingRoom', 'text', 'firstName', 'lastName', 'fullName', 'idNumber', 'barcodeNumber', 'qrCode', 'title', 'class', 'transportation', 'middleName', 'department', 'email', 'phone', 'address', 'dateOfBirth', 'issueDate', 'expirationDate', 'emergencyContact', 'bloodType', 'campus'].sort(function (a, b) {
  return LABELS[a].localeCompare(LABELS[b]);
});
const NON_COLUMN_ELEMENTS = ['schoolYear', 'logo', 'image', 'photo', 'signature', 'instructions', 'divider', 'rectangle', 'circle', 'icon'];
const NON_TEXT_ELEMENTS = ['signature', 'divider', 'rectangle', 'circle', 'logo', 'image', 'photo', 'barcodeNumber', 'qrCode', 'transportation', 'class'];
let design = {
  designId: crypto.randomUUID(),
  name: 'New ID Card',
  cardType: 'portrait-hole',
  dataSource: 'universal',
  cardColor: '#ffffff',
  borderColor: '#98a2b3',
  cornerRadius: 12,
  typographyDefaultsVersion: TYPOGRAPHY_DEFAULTS_VERSION,
  elements: [],
  frontElements: [],
  backElements: []
};
let activeSide = 'front';
let selectedId = null;
let interaction = null;
let currentPhoto = '';
let photoRequest = 0;
let designerDataRequest = 0;
let currentDesignFileHandle = null;
let currentDesignFileName = '';
let designTabs = [];
let activeDesignTabId = '';
let alignmentGuideTimer = null;
const card = document.getElementById('designCard');
const val = id => document.getElementById(id).value;
const setVal = (id, v) => {
  const e = document.getElementById(id);
  if (e && v !== undefined) e.value = v;
};
function buildFontSizeMenus() {
  ['standardSize', 'classLabelSize', 'classValueSize'].forEach(id => {
    const input = document.getElementById(id);
    if (input) input.value = String(clampFontSize(input.value || 12, 12));
  });
}
function uid() {
  return 'el_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7);
}
function spec() {
  return CARD_TYPES[design.cardType];
}
function textElement(type) {
  return !NON_TEXT_ELEMENTS.includes(type);
}
function clampFontSize(value, fallback) {
  const number = Number(value);
  return Math.max(FONT_SIZE_MIN, Math.min(FONT_SIZE_MAX, Number.isFinite(number) ? number : fallback || 12));
}
function ensureElementSettings(model) {
  if (!model) return model;
  if (model.fontFamily === undefined) model.fontFamily = 'Segoe UI, Arial, sans-serif';
  model.fontSize = clampFontSize(model.fontSize, 12);
  if (model.color === undefined) model.color = '#111827';
  if (model.fontWeight === undefined) model.fontWeight = '400';
  if (model.align === undefined) model.align = 'center';
  if (model.verticalAlign === undefined) model.verticalAlign = 'center';
  if (model.opacity === undefined) model.opacity = 1;
  if (model.backgroundColor === undefined) model.backgroundColor = 'transparent';
  if (model.borderColor === undefined) model.borderColor = '#667085';
  if (model.borderWidth === undefined) model.borderWidth = 0;
  if (model.type === 'schoolYear' && model.text === undefined) model.text = '';
  if (model.type === 'transportation') {
    if (model.transportBusValues === undefined) model.transportBusValues = 'Bus, School Bus';
    if (model.transportWalkValues === undefined) model.transportWalkValues = 'Walk, Walking, Walker';
    if (model.transportPickupValues === undefined) model.transportPickupValues = 'Pick Up, Pickup, Car, Car Rider, Parent Pickup';
    if (model.transportNoneValues === undefined) model.transportNoneValues = 'None, N/A, No Transportation';
  }
  if (model.type === 'class') {
    if (model.classLabelFont === undefined) model.classLabelFont = 'Segoe UI, Arial, sans-serif';
    model.classLabelSize = clampFontSize(model.classLabelSize, 12);
    if (model.classLabelColor === undefined) model.classLabelColor = '#185adb';
    if (model.classLabelWeight === undefined) model.classLabelWeight = '700';
    if (model.classLabelItalic === undefined) model.classLabelItalic = false;
    if (model.classLabelAlign === undefined) model.classLabelAlign = 'flex-end';
    if (model.classLabelVerticalAlign === undefined) model.classLabelVerticalAlign = 'center';
    if (model.classValueFont === undefined) model.classValueFont = 'Segoe UI, Arial, sans-serif';
    model.classValueSize = clampFontSize(model.classValueSize, 12);
    if (model.classValueColor === undefined) model.classValueColor = '#111827';
    if (model.classValueWeight === undefined) model.classValueWeight = '900';
    if (model.classValueItalic === undefined) model.classValueItalic = false;
    if (model.classValueAlign === undefined) model.classValueAlign = 'flex-start';
    if (model.classValueVerticalAlign === undefined) model.classValueVerticalAlign = 'center';
  }
  return model;
}
function applyTypographyDefaults(target) {
  target.frontElements.concat(target.backElements).forEach(function (model) {
    if (!model) return;
    if (model.type === 'class') {
      model.classLabelSize = clampFontSize(model.classLabelSize, 12);
      model.classValueSize = clampFontSize(model.classValueSize, 12);
    } else if (textElement(model.type)) {
      model.fontSize = clampFontSize(model.fontSize, 12);
    }
  });
  target.typographyDefaultsVersion = TYPOGRAPHY_DEFAULTS_VERSION;
  return target;
}
function ensureTwoSides(target) {
  target.frontElements = Array.isArray(target.frontElements) ? target.frontElements : Array.isArray(target.elements) ? target.elements : [];
  target.backElements = Array.isArray(target.backElements) ? target.backElements : [];
  applyTypographyDefaults(target);
  target.frontElements.forEach(ensureElementSettings);
  target.backElements.forEach(ensureElementSettings);
  target.elements = target.frontElements;
  return target;
}
function currentElements() {
  ensureTwoSides(design);
  return activeSide === 'back' ? design.backElements : design.frontElements;
}
function switchCardSide(side) {
  if (side !== 'front' && side !== 'back') return;
  captureSelectedInspectorValues();
  activeSide = side;
  selectedId = null;
  document.getElementById('frontSideTab').classList.toggle('active', side === 'front');
  document.getElementById('backSideTab').classList.toggle('active', side === 'back');
  render();
}
function createModel(type) {
  const d = DEFAULTS[type];
  const s = spec();
  return ensureElementSettings({
    id: uid(),
    type,
    text: d.text || '',
    imageData: '',
    columnIndex: '',
    x: Math.round((s.width - d.w) / 2),
    y: Math.round((s.height - d.h) / 2),
    w: d.w,
    h: d.h,
    fontSize: d.fontSize || 12,
    color: d.color || '#111827',
    backgroundColor: d.backgroundColor || 'transparent',
    borderColor: '#667085',
    borderWidth: 0,
    opacity: 1,
    verticalAlign: 'center',
    fontWeight: d.fontWeight || '400',
    fontFamily: 'Segoe UI, Arial, sans-serif',
    italic: false,
    underline: false,
    strike: false,
    align: 'center',
    rotation: 0,
    z: currentElements().length + 1,
    transportBusValues: 'Bus, School Bus',
    transportWalkValues: 'Walk, Walking, Walker',
    transportPickupValues: 'Pick Up, Pickup, Car, Car Rider, Parent Pickup',
    transportNoneValues: 'None, N/A, No Transportation',
    classLabelFont: 'Segoe UI, Arial, sans-serif',
    classLabelSize: 12,
    classLabelColor: '#185adb',
    classLabelWeight: '700',
    classLabelItalic: false,
    classLabelAlign: 'flex-end',
    classLabelVerticalAlign: 'center',
    classValueFont: 'Segoe UI, Arial, sans-serif',
    classValueSize: 12,
    classValueColor: '#111827',
    classValueWeight: '900',
    classValueItalic: false,
    classValueAlign: 'flex-start',
    classValueVerticalAlign: 'center'
  });
}
function addElement(type) {
  if (!DEFAULTS[type]) return;
  const m = createModel(type);
  m.columnIndex = '';
  currentElements().push(m);
  selectedId = m.id;
  if (type === 'photo') loadCurrentPhoto();
  render();
  flashElementAlignment(m);
}
function normalized(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, ' ');
}
function fillColumnSelect(select, type, currentValue) {
  if (!select) return;
  select.innerHTML = '<option value="">Mapped later in Card Studio</option>';
  select.value = '';
  select.disabled = true;
  select.title = 'Spreadsheet columns are mapped after this design is selected in a Card Studio.';
}
function buildElementButtons(boxId, types) {
  const box = document.getElementById(boxId);
  box.innerHTML = '';
  types.forEach(function (type) {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = LABELS[type];
    const help = {
      logo: 'Choose a logo image from your device and add it to the current card side.',
      image: 'Choose an image from your device and add it to the current card side.',
      schoolYear: 'Add an academic year. Enter its value in Content & Data.',
      photo: 'Add a photo frame. In a Card Studio it displays the selected record photo from the connected folder.',
      barcodeNumber: 'Add a Code 128 barcode. Map its value to a spreadsheet column in a Card Studio.',
      qrCode: 'Add a QR code. Map its text or URL to a spreadsheet column in a Card Studio.',
      class: 'Add the Grade label and a grade-level value. Their fonts, colors, and alignment can be adjusted separately.',
      transportation: 'Add a transportation icon. Define its matching values in the tools, then map a column in a Card Studio.',
      fullName: 'Add a full name from one spreadsheet column. This field does not join separate name columns.',
      text: 'Add text supplied by a spreadsheet column. Map the column in a Card Studio.'
    };
    button.title = help[type] || 'Add ' + LABELS[type] + '. Map its value to a spreadsheet column in a Card Studio.';
    button.onclick = function () {
      if (type === 'logo') chooseLogo();else if (type === 'signature') chooseSignature();else if (type === 'image') chooseImage();else addElement(type);
    };
    box.appendChild(button);
  });
}
function buildNewElementPicker() {
  buildElementButtons('designElementOptions', DESIGN_ELEMENT_ORDER);
  buildElementButtons('dataElementOptions', DATA_ELEMENT_ORDER);
}

function chooseLogo() {
  document.getElementById('designLogoInput').click();
}
let signatureReplaceTarget = null;
function chooseSignature(replaceSelected) {
  signatureReplaceTarget = replaceSelected && selected() && selected().type === 'signature' ? selected() : null;
  document.getElementById('signatureImageInput').click();
}
function finishSignatureUpload(event) {
  const file = event.target.files[0];
  if (!file) return;
  const target = signatureReplaceTarget;
  signatureReplaceTarget = null;
  event.target.value = '';
  if (!file.type.startsWith('image/')) {
    alert('Choose an image file for the signature.');
    return;
  }
  const tabId = activeDesignTabId;
  prepareCardImageFile(file, function(imageData) {
    if (activeDesignTabId !== tabId) {
      alert('Return to the original design tab and upload the signature again.');
      return;
    }
    if (target && !currentElements().includes(target)) return;
    const model = target || createModel('signature');
    model.imageData = imageData;
    if (!target) currentElements().push(model);
    selectedId = model.id;
    render();
  });
}
function setSelectedSymbol(value) {
  const model = selected();
  if (!model || model.type !== 'icon') return;
  model.text = value;
  render();
}
function chooseImage() {
  document.getElementById('designImageInput').click();
}
function finishImageUpload(event) {
  const file = event.target.files[0];
  if (!file) return;
  if (!file.type.startsWith('image/')) {
    document.getElementById('saveStatus').textContent = 'Please choose an image file.';
    event.target.value = '';
    return;
  }
  prepareCardImageFile(file, function (imageData) {
    const m = createModel('image');
    m.imageData = imageData;
    currentElements().push(m);
    selectedId = m.id;
    render();
    flashElementAlignment(m);
    document.getElementById('saveStatus').textContent = 'Image added to the ' + (activeSide === 'front' ? 'Front Side.' : 'Back Side.');
  });
  event.target.value = '';
}
function prepareCardImageFile(file, onReady) {
  const reader = new FileReader();
  reader.onload = function (event) {
    const original = event.target.result;
    const image = new Image();
    image.onload = function () {
      const scale = Math.min(1, 1600 / Math.max(image.naturalWidth, image.naturalHeight));
      const canvas = document.createElement('canvas');
      const context = canvas.getContext('2d');
      canvas.width = Math.max(1, Math.round(image.naturalWidth * scale));
      canvas.height = Math.max(1, Math.round(image.naturalHeight * scale));
      context.drawImage(image, 0, 0, canvas.width, canvas.height);
      onReady(canvas.toDataURL(file.type === 'image/jpeg' ? 'image/jpeg' : 'image/png', .9));
    };
    image.onerror = function () {
      onReady(original);
    };
    image.src = original;
  };
  reader.readAsDataURL(file);
}
function finishLogoUpload(event) {
  const file = event.target.files[0];
  if (!file) return;
  if (!file.type.startsWith('image/')) {
    document.getElementById('saveStatus').textContent = 'Please choose an image file.';
    event.target.value = '';
    return;
  }
  prepareDesignLogoFile(file, function (logoData) {
    addElement('logo');
    selected().imageData = logoData;
    render();
    document.getElementById('saveStatus').textContent = 'Card logo added. Select the logo element to resize, rotate, or reposition it.';
  });
  event.target.value = '';
}
function prepareDesignLogoFile(file, onReady) {
  const reader = new FileReader();
  reader.onload = function (event) {
    const original = event.target.result;
    const image = new Image();
    image.onload = function () {
      try {
        const scale = Math.min(1, 1000 / Math.max(image.naturalWidth, image.naturalHeight));
        const width = Math.max(1, Math.round(image.naturalWidth * scale));
        const height = Math.max(1, Math.round(image.naturalHeight * scale));
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d', {
          willReadFrequently: true
        });
        canvas.width = width;
        canvas.height = height;
        context.drawImage(image, 0, 0, width, height);
        const pixels = context.getImageData(0, 0, width, height).data;
        let minX = width;
        let minY = height;
        let maxX = -1;
        let maxY = -1;
        for (let y = 0; y < height; y += 1) {
          for (let x = 0; x < width; x += 1) {
            const i = (y * width + x) * 4;
            const visible = pixels[i + 3] > 12;
            const white = pixels[i] > 248 && pixels[i + 1] > 248 && pixels[i + 2] > 248;
            if (visible && !white) {
              minX = Math.min(minX, x);
              minY = Math.min(minY, y);
              maxX = Math.max(maxX, x);
              maxY = Math.max(maxY, y);
            }
          }
        }
        if (maxX < minX || maxY < minY) {
          onReady(original);
          return;
        }
        const pad = Math.max(2, Math.round(Math.max(maxX - minX + 1, maxY - minY + 1) * .02));
        minX = Math.max(0, minX - pad);
        minY = Math.max(0, minY - pad);
        maxX = Math.min(width - 1, maxX + pad);
        maxY = Math.min(height - 1, maxY + pad);
        const sourceX = minX / scale;
        const sourceY = minY / scale;
        const sourceWidth = (maxX - minX + 1) / scale;
        const sourceHeight = (maxY - minY + 1) / scale;
        const outputScale = Math.min(1, 1600 / Math.max(sourceWidth, sourceHeight));
        const output = document.createElement('canvas');
        const outputContext = output.getContext('2d');
        output.width = Math.max(1, Math.round(sourceWidth * outputScale));
        output.height = Math.max(1, Math.round(sourceHeight * outputScale));
        outputContext.drawImage(image, sourceX, sourceY, sourceWidth, sourceHeight, 0, 0, output.width, output.height);
        onReady(output.toDataURL('image/png'));
      } catch (error) {
        onReady(original);
      }
    };
    image.onerror = function () {
      onReady(original);
    };
    image.src = original;
  };
  reader.readAsDataURL(file);
}

function logoData() {
  return design.logoData || '';
}
function recordValue(type, model) {
  // The designer uses sample labels; real values are supplied only by the
  // selected Card Studio's explicit, source-scoped column mapping.
  if (type === 'instructions' || type === 'icon') return model && model.text || '';
  if (type === 'schoolYear') return model && model.text || 'Enter the academic year, e.g. 2026–2027';
  if (type === 'idNumber') return 'ID #: ID Number';
  if (type === 'barcodeNumber') return '123456789';
  if (type === 'qrCode') return 'QR Code';
  if (type === 'class') return 'Level';
  if (type === 'transportation') return 'Bus';
  return LABELS[type] || 'Data';
}
function fitDesignerText(host, text, maxFontSize, autoJustify, preferredAlign) {
  if (!host || !text || !String(text.textContent || '').trim()) return;
  // Store the user's maximum, never the temporarily reduced display size.
  text.dataset.fitMaxFontSize = String(maxFontSize || 12);
  text.dataset.fitAlign = preferredAlign || '';
  text.dataset.fitSelf = host === text ? 'true' : 'false';
  const applyFit = function () {
    const max = Math.max(1, Number(maxFontSize) || 12);
    const availableWidth = host.clientWidth;
    const availableHeight = host.clientHeight;
    if (availableWidth < 1 || availableHeight < 1) return;
    text.style.maxWidth = '100%';
    text.style.maxHeight = 'none';
    text.style.overflow = 'visible';
    text.style.flexShrink = '0';
    text.style.boxSizing = 'border-box';
    text.style.letterSpacing = 'normal';
    text.style.wordSpacing = 'normal';
    text.style.overflowWrap = 'anywhere';
    text.style.wordBreak = 'normal';
    text.style.textAlign = preferredAlign || text.style.textAlign || 'center';
    text.style.textAlignLast = 'auto';
    text.style.textJustify = 'inter-word';
    text.classList.remove('auto-justified');
    // Leave a small margin for browser rounding and glyph descenders.
    const heightLimit = Math.max(1, availableHeight - 1);
    // A full-width text block has scrollWidth == host width even without overflow.
    const fitsContent = function () {
      return text.scrollWidth <= availableWidth && text.scrollHeight <= heightLimit;
    };
    text.style.fontSize = max + 'px';
    if (!fitsContent()) {
      let low = 0.1;
      let high = max;
      let best = low;
      for (let pass = 0; pass < 18; pass++) {
        const candidate = (low + high) / 2;
        text.style.fontSize = candidate + 'px';
        if (fitsContent()) { best = candidate; low = candidate; }
        else high = candidate;
      }
      text.style.fontSize = Math.max(0.1, Math.floor(best * 100) / 100) + 'px';
    }
    // The font size fits the entire content; do not crop the final text line.
    text.style.maxHeight = 'none';
    text.style.overflow = 'visible';
  };
  applyFit();
  if (typeof requestAnimationFrame === 'function') requestAnimationFrame(function () {
    if (text.isConnected) applyFit();
  });
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(function () {
    if (text.isConnected) applyFit();
  });
}
  function fitDesignerDataElement(node, model) {
  if (!node || !model || ['logo', 'image', 'photo', 'barcodeNumber', 'qrCode', 'transportation'].includes(model.type)) return;
  if (model.type === 'class') {
    const segments = node.querySelectorAll('.grade-segment');
    fitDesignerText(segments[0], segments[0], Number(model.classLabelSize || 12), false, '');
    fitDesignerText(segments[1], segments[1], Number(model.classValueSize || 12), false, '');
    return;
  }
  fitDesignerText(node, node.querySelector('.element-text'), Number(model.fontSize || 12), !NON_COLUMN_ELEMENTS.includes(model.type), model.align || 'center');
}

function render() {
  hideAlignmentGuides();
  const s = spec();
  const elements = currentElements();
  Object.assign(card.style, {
    width: s.width + 'px',
    height: s.height + 'px',
    background: design.cardColor,
    borderColor: design.borderColor,
    borderRadius: design.cornerRadius + 'px'
  });
  card.classList.toggle('landscape-card', s.width > s.height);
  document.getElementById('lanyard').hidden = !s.hole;
  document.getElementById('workspaceTitle').textContent = design.name + ' — ' + (activeSide === 'front' ? 'Front Side' : 'Back Side');
  document.getElementById('sizeLabel').textContent = s.label;
  card.querySelectorAll('.design-element').forEach(n => n.remove());
  elements.slice().sort((a, b) => a.z - b.z).forEach(m => {
    const n = renderElement(m);
    card.appendChild(n);
    if (m.type === 'barcodeNumber') drawBarcode(n, m);
    if (m.type === 'qrCode') drawQrCode(n, m);
    fitDesignerDataElement(n, m);
  });
  renderLayers();
  syncInspector();
}
function renderElement(m) {
  const n = document.createElement('div');
  n.className = 'design-element ' + m.type + ' ' + (m.id === selectedId ? 'selected' : '');
  n.dataset.id = m.id;
  Object.assign(n.style, {
    left: m.x + 'px',
    top: m.y + 'px',
    width: m.w + 'px',
    height: m.h + 'px',
    zIndex: String(m.z),
    color: m.color || '#111827',
    backgroundColor: m.backgroundColor || 'transparent',
    borderColor: m.borderColor || '#667085',
    borderStyle: Number(m.borderWidth || 0) > 0 ? 'solid' : 'none',
    borderWidth: Number(m.borderWidth || 0) + 'px',
    opacity: String(m.opacity === undefined ? 1 : m.opacity),
    fontSize: m.fontSize + 'px',
    fontWeight: m.fontWeight,
    fontFamily: m.fontFamily,
    fontStyle: m.italic ? 'italic' : 'normal',
    textDecoration: [m.underline ? 'underline' : '', m.strike ? 'line-through' : ''].filter(Boolean).join(' ') || 'none',
    textAlign: m.align,
    justifyContent: m.align === 'left' ? 'flex-start' : m.align === 'right' ? 'flex-end' : 'center',
    alignItems: m.verticalAlign || 'center',
    transform: 'rotate(' + Number(m.rotation || 0) + 'deg)'
  });
  if (['divider', 'rectangle', 'circle'].includes(m.type)) {
    n.style.borderRadius = m.type === 'circle' ? '50%' : '0';
  } else if (m.type === 'logo') {
    const src = m.imageData || logoData();
    if (src) {
      const i = document.createElement('img');
      i.src = src;
      i.alt = 'Card logo';
      n.appendChild(i);
    } else n.textContent = 'LOGO';
  } else if (m.type === 'image' || m.type === 'signature') {
    if (m.imageData) {
      const i = document.createElement('img');
      i.src = m.imageData;
      i.alt = 'Card image';
      n.appendChild(i);
    } else n.textContent = m.type === 'signature' ? 'SIGNATURE' : 'IMAGE';
  } else if (m.type === 'photo') {
    const h = document.createElement('div');
    h.className = 'photo-placeholder';
    h.textContent = 'PHOTO';
    n.appendChild(h);
  } else if (m.type === 'barcodeNumber') {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.classList.add('barcode-svg');
    n.appendChild(svg);
  } else if (m.type === 'qrCode') {
    const qr = document.createElement('div');
    qr.className = 'qr-code';
    n.appendChild(qr);
  } else if (m.type === 'class') {
    const b = document.createElement('div');
    b.className = 'class-content';
    const l = document.createElement('span');
    const v = document.createElement('span');
    l.className = 'grade-segment grade-label-segment';
    v.className = 'grade-segment grade-value-segment';
    l.textContent = 'Grade';
    v.textContent = recordValue('class', m);
    const labelVertical = m.classLabelVerticalAlign || 'center';
    const valueVertical = m.classValueVerticalAlign || 'center';
    Object.assign(l.style, {
      fontFamily: m.classLabelFont || 'Segoe UI, Arial, sans-serif',
      fontSize: Number(m.classLabelSize || 12) + 'px',
      color: m.classLabelColor || '#185adb',
      fontWeight: m.classLabelWeight || '700',
      fontStyle: m.classLabelItalic ? 'italic' : 'normal',
      justifyContent: m.classLabelAlign || 'flex-end',
      alignItems: labelVertical
    });
    Object.assign(v.style, {
      fontFamily: m.classValueFont || 'Segoe UI, Arial, sans-serif',
      fontSize: Number(m.classValueSize || 12) + 'px',
      color: m.classValueColor || '#111827',
      fontWeight: m.classValueWeight || '900',
      fontStyle: m.classValueItalic ? 'italic' : 'normal',
      justifyContent: m.classValueAlign || 'flex-start',
      alignItems: valueVertical
    });
    if (labelVertical === valueVertical) {
      b.classList.add('grade-pair-aligned');
      Object.assign(b.style, {
        gridAutoRows: 'max-content',
        alignItems: 'baseline',
        alignContent: labelVertical === 'flex-start' ? 'start' : labelVertical === 'flex-end' ? 'end' : 'center'
      });
      Object.assign(l.style, {
        height: 'auto',
        alignItems: 'baseline'
      });
      Object.assign(v.style, {
        height: 'auto',
        alignItems: 'baseline'
      });
    }
    b.append(l, v);
    n.appendChild(b);
  } else if (m.type === 'transportation') n.innerHTML = transportDisplay(recordValue('transportation', m));else {
    const text = document.createElement('span');
    text.className = 'element-text' + (m.align === 'justify' ? ' justify' : '');
    text.textContent = recordValue(m.type, m);
    if (m.type === 'instructions') text.style.whiteSpace = 'pre-wrap';
    n.appendChild(text);
  }
  n.addEventListener('pointerdown', startMove);
  n.addEventListener('click', e => {
    e.stopPropagation();
    selectElement(m.id);
  });
  if (m.id === selectedId) {
    ['nw', 'n', 'ne', 'e', 'se', 's', 'sw', 'w'].forEach(function (corner) {
      const h = document.createElement('div');
      h.className = 'resize-handle ' + corner;
      h.dataset.corner = corner;
      h.title = corner.length === 1 ? 'Resize from side' : 'Resize from corner';
      h.addEventListener('pointerdown', startResize);
      n.appendChild(h);
    });
    const rotate = document.createElement('div');
    rotate.className = 'rotate-handle';
    rotate.title = 'Drag to rotate. Common angles snap automatically.';
    rotate.setAttribute('aria-label', 'Rotate element');
    rotate.dataset.angle = Math.round(Number(m.rotation || 0)) + '°';
    rotate.textContent = '↻';
    rotate.addEventListener('pointerdown', startRotate);
    n.appendChild(rotate);
  }
  return n;
}
function drawBarcode(n, m) {
  const svg = n.querySelector('svg');
  const value = recordValue('barcodeNumber', m);
  if (!svg || !value || typeof JsBarcode !== 'function') return;
  try {
    JsBarcode(svg, value, {
      format: 'CODE128',
      width: 1.25,
      height: Math.max(18, m.h),
      displayValue: false,
      margin: 0
    });
  } catch (e) {
    svg.textContent = 'Invalid barcode';
  }
}
function drawQrCode(n, m) {
  const host = n.querySelector('.qr-code');
  const value = recordValue('qrCode', m);
  if (!host || !value) return;
  if (typeof qrcode !== 'function') {
    host.textContent = 'QR';
    return;
  }
  try {
    const qr = qrcode(0, 'M');
    qr.addData(value);
    qr.make();
    host.innerHTML = qr.createSvgTag({
      cellSize: 2,
      margin: 0,
      scalable: true
    });
    const svg = host.querySelector('svg');
    if (svg) {
      svg.setAttribute('width', '100%');
      svg.setAttribute('height', '100%');
      svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
    }
  } catch (error) {
    host.textContent = 'Invalid QR data';
  }
}
function transportSvg(t, m) {
  const a = 'viewBox="0 0 24 24" role="img" aria-label="' + t + '"';
  if (t === 'Bus') return '<div class="transport-icon" title="Bus"><svg ' + a + ' fill="#e67e22"><path d="M4 16c0 1.1.9 2 2 2h1v1a1 1 0 0 0 2 0v-1h6v1a1 1 0 0 0 2 0v-1h1c1.1 0 2-.9 2-2V6c0-3.5-3.6-4-8-4S4 2.5 4 6v10zm3 1a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3zm10 0a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3zm1-6H6V6h12v5z"/></svg></div>';
  if (t === 'Walking') {
    if (m && m.transportWalkingIconType === 'custom' && m.transportWalkingIconData) return '<div class="transport-icon" title="Walking"><img src="' + m.transportWalkingIconData + '" alt="Walking"></div>';
    return '<div class="transport-icon" title="Walking"><svg ' + a + ' fill="#27ae60"><circle cx="12" cy="3.5" r="2"/><path d="M10.2 7.1c.8-.7 2.8-.7 3.6 0l1.6 1.7c.8.8 1.8 1.3 3 1.4l-.2 2c-1.7-.1-3.2-.8-4.4-2l-.3-.3-.5 3 2.3 2.4V22h-2.2v-5.7l-2-1.9-1 3.2L7.7 22H5.2l2.9-5.4 1.1-5.8-1.4 1.4c-.8.8-1.8 1.3-2.9 1.5l-.4-2c.8-.2 1.4-.5 2-1.1l3.7-3.5z"/></svg></div>';
  }
  if (t === 'Pick Up') return '<div class="transport-icon" title="Pick Up"><svg ' + a + ' fill="#185adb"><path d="M5 11l1.5-4.5h11L19 11H5zm14.5 1h-15C3.67 12 3 12.67 3 13.5V18h2v1a1 1 0 0 0 2 0v-1h10v1a1 1 0 0 0 2 0v-1h2v-4.5c0-.83-.67-1.5-1.5-1.5zM6.5 16a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3zm11 0a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3z"/></svg></div>';
  return '';
}
function transportDisplay(t) {
  if (t === 'Bus') return '<div class="transport-icon" title="Bus"><svg viewBox="0 0 24 24" role="img" aria-label="Bus"><text x="12" y="19" text-anchor="middle" font-size="20">🚌</text></svg></div>';
  if (t === 'Pick Up') return '<div class="transport-icon" title="Pick Up"><svg viewBox="0 0 24 24" role="img" aria-label="Pick Up"><text x="12" y="19" text-anchor="middle" font-size="20">🚗</text></svg></div>';
  return transportSvg(t, {});
}
function loadCurrentPhoto() {
  currentPhoto = '';
}
function selectElement(id) {
  if (id !== selectedId) captureSelectedInspectorValues();
  selectedId = id;
  render();
}
function clearSelection(e) {
  if (e.target === card) {
    captureSelectedInspectorValues();
    selectedId = null;
    render();
  }
}
function selected() {
  return currentElements().find(x => x.id === selectedId);
}
function startMove(e) {
  if (e.target.classList.contains('resize-handle') || e.target.classList.contains('rotate-handle')) return;
  e.preventDefault();
  e.stopPropagation();
  const m = currentElements().find(x => x.id === e.currentTarget.dataset.id);
  selectedId = m.id;
  interaction = {
    mode: 'move',
    id: m.id,
    startX: e.clientX,
    startY: e.clientY,
    x: m.x,
    y: m.y
  };
  card.querySelectorAll('.design-element').forEach(n => n.classList.toggle('selected', n.dataset.id === selectedId));
  e.currentTarget.setPointerCapture(e.pointerId);
  e.currentTarget.addEventListener('pointermove', continueInteraction);
  e.currentTarget.addEventListener('pointerup', endInteraction);
  renderLayers();
  syncInspector();
}
function startResize(e) {
  e.preventDefault();
  e.stopPropagation();
  const n = e.currentTarget.parentElement;
  const m = currentElements().find(x => x.id === n.dataset.id);
  interaction = {
    mode: 'resize',
    id: m.id,
    corner: e.currentTarget.dataset.corner || 'se',
    startX: e.clientX,
    startY: e.clientY,
    x: m.x,
    y: m.y,
    w: m.w,
    h: m.h,
    rotation: Number(m.rotation || 0)
  };
  n.setPointerCapture(e.pointerId);
  n.addEventListener('pointermove', continueInteraction);
  n.addEventListener('pointerup', endInteraction);
}
function startRotate(e) {
  e.preventDefault();
  e.stopPropagation();
  const n = e.currentTarget.parentElement;
  const m = currentElements().find(x => x.id === n.dataset.id);
  const rect = n.getBoundingClientRect();
  const centerX = rect.left + rect.width / 2;
  const centerY = rect.top + rect.height / 2;
  interaction = {
    mode: 'rotate',
    id: m.id,
    centerX: centerX,
    centerY: centerY,
    startAngle: Math.atan2(e.clientY - centerY, e.clientX - centerX) * 180 / Math.PI,
    rotation: Number(m.rotation || 0)
  };
  n.setPointerCapture(e.pointerId);
  n.addEventListener('pointermove', continueInteraction);
  n.addEventListener('pointerup', endInteraction);
}
function snapRotationAngle(value) {
  let angle = ((Number(value) + 180) % 360 + 360) % 360 - 180;
  const snapAngles = [-180, -135, -90, -45, 0, 45, 90, 135, 180];
  const threshold = 7;
  let closest = angle;
  let distance = Infinity;
  snapAngles.forEach(function (target) {
    const nextDistance = Math.abs(angle - target);
    if (nextDistance < distance) {
      distance = nextDistance;
      closest = target;
    }
  });
  return distance <= threshold ? closest : Math.round(angle);
}
function allowsUnlimitedPosition() {
  return true;
}
function hideAlignmentGuides() {
  const vertical = document.getElementById('verticalGuide');
  const horizontal = document.getElementById('horizontalGuide');
  if (vertical) vertical.style.display = 'none';
  if (horizontal) horizontal.style.display = 'none';
  if (alignmentGuideTimer) {
    clearTimeout(alignmentGuideTimer);
    alignmentGuideTimer = null;
  }
}
function showAlignmentGuides(verticalAt, horizontalAt, duration) {
  const s = spec();
  const vertical = document.getElementById('verticalGuide');
  const horizontal = document.getElementById('horizontalGuide');
  if (vertical) {
    if (verticalAt === null) {
      vertical.style.display = 'none';
    } else {
      vertical.style.left = Math.max(0, Math.min(s.width - 1, verticalAt)) + 'px';
      vertical.style.display = 'block';
    }
  }
  if (horizontal) {
    if (horizontalAt === null) {
      horizontal.style.display = 'none';
    } else {
      horizontal.style.top = Math.max(0, Math.min(s.height - 1, horizontalAt)) + 'px';
      horizontal.style.display = 'block';
    }
  }
  if (duration) {
    if (alignmentGuideTimer) clearTimeout(alignmentGuideTimer);
    alignmentGuideTimer = setTimeout(hideAlignmentGuides, duration);
  }
}
function alignedPosition(model, nextX, nextY) {
  const s = spec();
  const threshold = 16;
  const xTargets = [0, s.width / 2, s.width];
  const yTargets = [0, s.height / 2, s.height];
  currentElements().forEach(function (item) {
    if (item.id === model.id) return;
    xTargets.push(item.x, item.x + item.w / 2, item.x + item.w);
    yTargets.push(item.y, item.y + item.h / 2, item.y + item.h);
  });
  const xOffsets = [0, model.w / 2, model.w];
  const yOffsets = [0, model.h / 2, model.h];
  let bestX = null;
  let bestY = null;
  xTargets.forEach(function (target) {
    xOffsets.forEach(function (offset) {
      const delta = target - (nextX + offset);
      const distance = Math.abs(delta);
      if (distance <= threshold && (!bestX || distance < bestX.distance)) bestX = {
        distance: distance,
        value: nextX + delta,
        line: target
      };
    });
  });
  yTargets.forEach(function (target) {
    yOffsets.forEach(function (offset) {
      const delta = target - (nextY + offset);
      const distance = Math.abs(delta);
      if (distance <= threshold && (!bestY || distance < bestY.distance)) bestY = {
        distance: distance,
        value: nextY + delta,
        line: target
      };
    });
  });
  return {
    x: bestX ? bestX.value : nextX,
    y: bestY ? bestY.value : nextY,
    vertical: bestX ? bestX.line : null,
    horizontal: bestY ? bestY.line : null
  };
}
function flashElementAlignment(model) {
  const aligned = alignedPosition(model, model.x, model.y);
  showAlignmentGuides(aligned.vertical, aligned.horizontal, 2200);
}
function continueInteraction(e) {
  if (!interaction) return;
  const m = design.elements.find(x => x.id === interaction.id);
  const s = spec();
  const dx = e.clientX - interaction.startX;
  const dy = e.clientY - interaction.startY;
  if (interaction.mode === 'move') {
    const nextX = Math.round(interaction.x + dx);
    const nextY = Math.round(interaction.y + dy);
    if (allowsUnlimitedPosition(m)) {
      m.x = nextX;
      m.y = nextY;
    } else {
      m.x = Math.max(0, Math.min(s.width - m.w, nextX));
      m.y = Math.max(0, Math.min(s.height - m.h, nextY));
    }
  } else {
    m.w = Math.max(20, Math.min(s.width - m.x, Math.round(interaction.w + dx)));
    m.h = Math.max(18, Math.min(s.height - m.y, Math.round(interaction.h + dy)));
  }
  const n = card.querySelector('[data-id="' + m.id + '"]');
  if (n) Object.assign(n.style, {
    left: m.x + 'px',
    top: m.y + 'px',
    width: m.w + 'px',
    height: m.h + 'px'
  });
  syncInspector();
}
function continueSideInteraction(e) {
  if (!interaction) return;
  const m = currentElements().find(x => x.id === interaction.id);
  if (!m) return;
  const cardRect = card.getBoundingClientRect();
  const cardSpec = spec();
  const scaleX = cardRect.width ? cardSpec.width / cardRect.width : 1;
  const scaleY = cardRect.height ? cardSpec.height / cardRect.height : 1;
  const dx = (e.clientX - interaction.startX) * scaleX;
  const dy = (e.clientY - interaction.startY) * scaleY;
  if (interaction.mode === 'move') {
    const aligned = alignedPosition(m, interaction.x + dx, interaction.y + dy);
    m.x = Math.round(aligned.x);
    m.y = Math.round(aligned.y);
    showAlignmentGuides(aligned.vertical, aligned.horizontal);
  } else if (interaction.mode === 'rotate') {
    hideAlignmentGuides();
    const pointerAngle = Math.atan2(e.clientY - interaction.centerY, e.clientX - interaction.centerX) * 180 / Math.PI;
    let rotation = interaction.rotation + (pointerAngle - interaction.startAngle);
    m.rotation = snapRotationAngle(rotation);
  } else {
    hideAlignmentGuides();
    /* Keep the diagonally opposite corner fixed and resize in the element's
       rotated coordinate system. This makes every handle track the pointer
       naturally at any angle, including negative and 180-degree rotations. */
    const angle = interaction.rotation * Math.PI / 180;
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);
    const west = interaction.corner.includes('w');
    const east = interaction.corner.includes('e');
    const north = interaction.corner.includes('n');
    const south = interaction.corner.includes('s');
    const resizeX = west || east;
    const resizeY = north || south;
    const signX = west ? -1 : 1;
    const signY = north ? -1 : 1;
    const startCenterX = interaction.x + interaction.w / 2;
    const startCenterY = interaction.y + interaction.h / 2;
    const oppositeLocalX = resizeX ? -signX * interaction.w / 2 : 0;
    const oppositeLocalY = resizeY ? -signY * interaction.h / 2 : 0;
    const oppositeX = startCenterX + oppositeLocalX * cos - oppositeLocalY * sin;
    const oppositeY = startCenterY + oppositeLocalX * sin + oppositeLocalY * cos;
    const pointerX = (e.clientX - cardRect.left) * scaleX;
    const pointerY = (e.clientY - cardRect.top) * scaleY;
    const pointerLocalX = (pointerX - oppositeX) * cos + (pointerY - oppositeY) * sin;
    const pointerLocalY = -(pointerX - oppositeX) * sin + (pointerY - oppositeY) * cos;
    const newW = resizeX ? Math.max(20, Math.min(2000, signX * pointerLocalX)) : interaction.w;
    const newH = resizeY ? Math.max(18, Math.min(2000, signY * pointerLocalY)) : interaction.h;
    const centerOffsetX = resizeX ? signX * newW / 2 : 0;
    const centerOffsetY = resizeY ? signY * newH / 2 : 0;
    const centerX = oppositeX + centerOffsetX * cos - centerOffsetY * sin;
    const centerY = oppositeY + centerOffsetX * sin + centerOffsetY * cos;
    m.w = Math.round(newW);
    m.h = Math.round(newH);
    m.x = Math.round(centerX - newW / 2);
    m.y = Math.round(centerY - newH / 2);
  }
  const n = card.querySelector('[data-id="' + m.id + '"]');
  if (n) {
    Object.assign(n.style, {
      left: m.x + 'px',
      top: m.y + 'px',
      width: m.w + 'px',
      height: m.h + 'px',
      transform: 'rotate(' + Number(m.rotation || 0) + 'deg)'
    });
    const rotationHandle = n.querySelector('.rotate-handle');
    if (rotationHandle) rotationHandle.dataset.angle = Math.round(Number(m.rotation || 0)) + '°';
    fitDesignerDataElement(n, m);
  }
  syncInspector();
}
continueInteraction = continueSideInteraction;
function endInteraction(e) {
  e.currentTarget.removeEventListener('pointermove', continueInteraction);
  e.currentTarget.removeEventListener('pointerup', endInteraction);
  interaction = null;
  hideAlignmentGuides();
  render();
}
function syncInspector() {
  const m = selected();
  document.getElementById('noSelection').hidden = !!m;
  document.getElementById('inspector').hidden = !m;
  if (!m) return;
  ensureElementSettings(m);
  const field = document.getElementById('elementField');
  const unlimited = allowsUnlimitedPosition(m);
  const xInput = document.getElementById('posX');
  const yInput = document.getElementById('posY');
  const hasEditableContent = ['schoolYear', 'instructions', 'icon'].includes(m.type);
  document.getElementById('selectedElementName').textContent = LABELS[m.type] || m.type;
  document.getElementById('editableElementContent').hidden = !hasEditableContent;
  document.getElementById('elementContentSettings').hidden = !hasEditableContent && m.type !== 'signature';
  document.getElementById('elementFieldLabel').textContent = hasEditableContent ? LABELS[m.type] : 'Element Name';
  field.disabled = !hasEditableContent;
  field.rows = m.type === 'instructions' ? 4 : 1;
  document.getElementById('signatureTools').hidden = m.type !== 'signature';
  document.getElementById('symbolTools').hidden = m.type !== 'icon';
  document.getElementById('symbolChoice').value = m.text || '★';
  field.placeholder = m.type === 'schoolYear' ? 'Enter the academic year, e.g. 2026–2027' : hasEditableContent ? 'Enter the content to display' : 'Map this element later in the Card Studio';
  setVal('elementField', hasEditableContent ? m.text || '' : LABELS[m.type] || m.type);
  const noColumn = NON_COLUMN_ELEMENTS.includes(m.type);
  document.getElementById('elementColumnField').hidden = true;
  if (noColumn) m.columnIndex = '';
  fillColumnSelect(document.getElementById('elementColumn'), m.type, m.columnIndex);
  if (unlimited) {
    xInput.removeAttribute('min');
    xInput.removeAttribute('max');
    yInput.removeAttribute('min');
    yInput.removeAttribute('max');
  } else {
    xInput.min = 0;
    yInput.min = 0;
  }
  const isGrade = m.type === 'class';
  const isText = textElement(m.type);
  document.getElementById('fontFamilyField').hidden = true;
  document.getElementById('standardTypography').hidden = !isText;
  document.getElementById('standardTypographyTitle').textContent = (LABELS[m.type] || 'Element') + ' Text';
  document.getElementById('classTypography').hidden = !isGrade;
  document.getElementById('transportRules').hidden = m.type !== 'transportation';
  document.getElementById('orientationField').hidden = false;
  setVal('standardFont', m.fontFamily);
  setVal('standardSize', Number(m.fontSize || 12));
  setVal('standardColor', /^#[0-9a-f]{6}$/i.test(m.color || '') ? m.color : '#111827');
  setVal('standardWeight', String(m.fontWeight || '400'));
  document.getElementById('standardItalic').checked = !!m.italic;
  document.getElementById('standardUnderline').checked = !!m.underline;
  document.getElementById('standardStrike').checked = !!m.strike;
  setVal('standardHorizontalAlign', m.align || 'center');
  setVal('standardVerticalAlign', m.verticalAlign || 'center');
  setVal('orientation', String(m.rotation || 0));
  setVal('rotationSlider', String(m.rotation || 0));
  setVal('transportBusValues', m.transportBusValues || 'Bus, School Bus');
  setVal('transportWalkValues', m.transportWalkValues || 'Walk, Walking, Walker');
  setVal('transportPickupValues', m.transportPickupValues || 'Pick Up, Pickup, Car, Car Rider, Parent Pickup');
  setVal('transportNoneValues', m.transportNoneValues || 'None, N/A, No Transportation');
  ['posX', 'posY', 'elementWidth', 'elementHeight'].forEach((id, i) => setVal(id, [m.x, m.y, m.w, m.h][i]));
  setVal('classLabelFont', m.classLabelFont);
  setVal('classLabelSize', Number(m.classLabelSize));
  setVal('classLabelColor', m.classLabelColor);
  setVal('classLabelWeight', m.classLabelWeight);
  document.getElementById('classLabelItalic').checked = !!m.classLabelItalic;
  setVal('classLabelAlign', m.classLabelAlign);
  setVal('classLabelVerticalAlign', m.classLabelVerticalAlign);
  setVal('classValueFont', m.classValueFont);
  setVal('classValueSize', Number(m.classValueSize));
  setVal('classValueColor', m.classValueColor);
  setVal('classValueWeight', m.classValueWeight);
  document.getElementById('classValueItalic').checked = !!m.classValueItalic;
  setVal('classValueAlign', m.classValueAlign);
  setVal('classValueVerticalAlign', m.classValueVerticalAlign);
  syncFormattingToolbar(m);
  if (window.syncCompactTextTools) window.syncCompactTextTools();
}
function syncFormattingToolbar(m) {
  document.querySelectorAll('.rotation-letter-button').forEach(button => {
    const preset = Number(button.dataset.rotation);
    const angle = Number(m.rotation || 0);
    const active = Math.abs(angle - preset) < 0.01 || (preset === 180 && Math.abs(angle + 180) < 0.01);
    button.setAttribute('aria-pressed', String(active));
  });
  const fillColor = /^#[0-9a-f]{6}$/i.test(m.backgroundColor || '') ? m.backgroundColor : '#ffffff';
  const fillColorInput = document.getElementById('toolbarFillColor');
  const borderButton = document.getElementById('toolbarBorder');
  fillColorInput.value = fillColor;
  borderButton.classList.toggle('active', Number(m.borderWidth || 0) > 0);
  borderButton.setAttribute('aria-pressed', String(Number(m.borderWidth || 0) > 0));
  const opacity = Math.round((m.opacity === undefined ? 1 : m.opacity) * 100);
  document.getElementById('toolbarOpacity').value = String(opacity);
  document.getElementById('toolbarOpacityValue').textContent = opacity + '%';
}

function setSelectedToolbarColor(property, value) {
  const m = selected();
  if (!m) return;
  m[property] = value;
  render();
}
function toggleSelectedBorder() {
  const m = selected();
  if (!m) return;
  if (Number(m.borderWidth || 0) > 0) {
    m.savedBorderWidth = Number(m.borderWidth);
    m.borderWidth = 0;
  } else {
    m.borderWidth = Number(m.savedBorderWidth) > 0 ? Number(m.savedBorderWidth) : 1;
  }
  render();
}

function stepBoxOpacity(delta) {
  const slider = document.getElementById('toolbarOpacity');
  slider.value = String(Math.max(Number(slider.min), Math.min(Number(slider.max), Number(slider.value) + delta)));
  setSelectedOpacity(slider.value);
}
function setSelectedOpacity(value) {
  const m = selected();
  if (!m) return;
  m.opacity = Math.max(.1, Math.min(1, Number(value) / 100));
  document.getElementById('toolbarOpacityValue').textContent = Math.round(m.opacity * 100) + '%';
  const node = card.querySelector('[data-id="' + m.id + '"]');
  if (node) node.style.opacity = String(m.opacity);
}
function captureSelectedInspectorValues() {
  const m = selected();
  if (!m) return null;
  ensureElementSettings(m);
  const s = spec();
  const previousColumn = m.columnIndex;
  const columnSelect = document.getElementById('elementColumn');
  if (NON_COLUMN_ELEMENTS.includes(m.type)) m.columnIndex = '';else if (columnSelect && !columnSelect.disabled) m.columnIndex = val('elementColumn');
  if (['schoolYear', 'instructions', 'icon'].includes(m.type)) m.text = val('elementField');
  if (textElement(m.type)) {
    m.fontFamily = val('standardFont') || m.fontFamily;
    m.fontSize = clampFontSize(val('standardSize'), 12);
    m.color = val('standardColor') || m.color;
    m.fontWeight = val('standardWeight') || m.fontWeight;
    m.italic = document.getElementById('standardItalic').checked;
    m.underline = document.getElementById('standardUnderline').checked;
    m.strike = document.getElementById('standardStrike').checked;
    m.align = val('standardHorizontalAlign') || 'center';
    m.verticalAlign = val('standardVerticalAlign') || 'center';
  }
  if (m.type === 'transportation') {
    m.transportBusValues = val('transportBusValues');
    m.transportWalkValues = val('transportWalkValues');
    m.transportPickupValues = val('transportPickupValues');
    m.transportNoneValues = val('transportNoneValues');
  }
  if (m.type === 'class') {
    m.classLabelFont = val('classLabelFont');
    m.classLabelSize = clampFontSize(val('classLabelSize'), 12);
    m.classLabelColor = val('classLabelColor');
    m.classLabelWeight = val('classLabelWeight');
    m.classLabelItalic = document.getElementById('classLabelItalic').checked;
    m.classLabelAlign = val('classLabelAlign') || 'flex-end';
    m.classLabelVerticalAlign = val('classLabelVerticalAlign') || 'center';
    m.classValueFont = val('classValueFont');
    m.classValueSize = clampFontSize(val('classValueSize'), 12);
    m.classValueColor = val('classValueColor');
    m.classValueWeight = val('classValueWeight');
    m.classValueItalic = document.getElementById('classValueItalic').checked;
    m.classValueAlign = val('classValueAlign') || 'flex-start';
    m.classValueVerticalAlign = val('classValueVerticalAlign') || 'center';
  }
  const angle = Number(val('orientation'));
  m.rotation = Number.isFinite(angle) ? Math.max(-180, Math.min(180, angle)) : 0;
  m.w = Math.max(20, Number(val('elementWidth')) || 20);
  m.h = Math.max(18, Number(val('elementHeight')) || 18);
  const inputX = Number(val('posX'));
  const inputY = Number(val('posY'));
  if (allowsUnlimitedPosition(m)) {
    if (Number.isFinite(inputX)) m.x = inputX;
    if (Number.isFinite(inputY)) m.y = inputY;
  } else {
    m.x = Math.max(0, Math.min(s.width - m.w, inputX || 0));
    m.y = Math.max(0, Math.min(s.height - m.h, inputY || 0));
  }
  return {
    model: m,
    photoColumnChanged: m.type === 'photo' && previousColumn !== m.columnIndex
  };
}
function updateSelectedFromInspector() {
  const result = captureSelectedInspectorValues();
  if (!result) return;
  render();
  if (result.photoColumnChanged) loadCurrentPhoto();
}
function setSelectedRotation(value) {
  const m = selected();
  if (!m) return;
  const angle = Math.max(-180, Math.min(180, Number(value) || 0));
  m.rotation = angle;
  setVal('orientation', String(angle));
  setVal('rotationSlider', String(angle));
  render();
}
function deleteSelected() {
  if (!selectedId) return;
  const elements = currentElements();
  const index = elements.findIndex(x => x.id === selectedId);
  if (index >= 0) elements.splice(index, 1);
  selectedId = null;
  render();
}

function renderLayers() {
  const elements = currentElements();
  const b = document.getElementById('layers');
  b.innerHTML = '';
  if (!elements.length) {
    b.innerHTML = '<div class="empty-state">No elements on this side</div>';
    return;
  }
  elements.forEach((x, index) => {
    const n = document.createElement('button');
    n.className = 'layer ' + (x.id === selectedId ? 'active' : '');
    n.innerHTML = '<span>' + LABELS[x.type] + '</span><span>#' + (index + 1) + '</span>';
    n.onclick = () => selectElement(x.id);
    b.appendChild(n);
  });
}
function changeCardType() {
  design.cardType = val('cardType');
  clamp();
  render();
}
function clamp() {
  [design.frontElements, design.backElements].forEach(elements => (elements || []).forEach(m => {
    m.w = Math.max(20, Number(m.w) || 20);
    m.h = Math.max(18, Number(m.h) || 18);
    m.x = Number.isFinite(Number(m.x)) ? Number(m.x) : 0;
    m.y = Number.isFinite(Number(m.y)) ? Number(m.y) : 0;
  }));
}
function updateCardStyle() {
  design.cardColor = val('cardColor');
  design.borderColor = val('borderColor');
  design.cornerRadius = Number(val('cornerRadius'));
  document.getElementById('cornerValue').textContent = design.cornerRadius + 'px';
  render();
}
function tabId() {
  return 'tab_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 6);
}
function captureActiveDesignTab() {
  captureSelectedInspectorValues();
  const tab = designTabs.find(item => item.id === activeDesignTabId);
  if (!tab) return;
  tab.design = design;
  tab.activeSide = activeSide;
  tab.selectedId = selectedId;
  tab.fileName = currentDesignFileName;
}
function renderDesignTabs() {
  const box = document.getElementById('designTabs');
  if (!box) return;
  captureActiveDesignTab();
  box.innerHTML = '';
  designTabs.forEach(function (tab, index) {
    const button = document.createElement('div');
    button.className = 'design-tab ' + (tab.id === activeDesignTabId ? 'active' : '');
    button.setAttribute('role', 'tab');
    button.setAttribute('aria-selected', tab.id === activeDesignTabId ? 'true' : 'false');
    button.title = tab.fileName || tab.design.name || 'Card ' + (index + 1);
    const name = document.createElement('button');
    name.type = 'button';
    name.className = 'design-tab-name';
    name.textContent = tab.design.name || 'Card ' + (index + 1);
    name.onclick = function () {
      switchDesignTab(tab.id);
    };
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'design-tab-close';
    close.title = 'Close this card';
    close.setAttribute('aria-label', 'Close ' + name.textContent);
    close.textContent = '×';
    close.onclick = function (event) {
      event.stopPropagation();
      closeDesignTab(tab.id);
    };
    button.append(name, close);
    box.appendChild(button);
  });
}
function addDesignTab(nextDesign, fileName) {
  captureActiveDesignTab();
  const tab = {
    id: tabId(),
    design: ensureTwoSides(Object.assign({
      designId: crypto.randomUUID()
    }, nextDesign)),
    activeSide: 'front',
    selectedId: null,
    fileName: fileName || ''
  };
  designTabs.push(tab);
  activeDesignTabId = tab.id;
  design = tab.design;
  activeSide = 'front';
  selectedId = null;
  currentDesignFileHandle = null;
  currentDesignFileName = tab.fileName;
  syncControls();
  document.getElementById('frontSideTab').classList.add('active');
  document.getElementById('backSideTab').classList.remove('active');
  renderDesignTabs();
  render();
}
function switchDesignTab(id) {
  if (id === activeDesignTabId) return;
  captureActiveDesignTab();
  const tab = designTabs.find(item => item.id === id);
  if (!tab) return;
  activeDesignTabId = id;
  design = tab.design;
  activeSide = tab.activeSide || 'front';
  selectedId = tab.selectedId || null;
  currentDesignFileHandle = null;
  currentDesignFileName = tab.fileName || '';
  syncControls();
  document.getElementById('frontSideTab').classList.toggle('active', activeSide === 'front');
  document.getElementById('backSideTab').classList.toggle('active', activeSide === 'back');
  renderDesignTabs();
  render();
}
function closeDesignTab(id) {
  captureActiveDesignTab();
  const index = designTabs.findIndex(item => item.id === id);
  if (index < 0) return;
  if (designTabs.length === 1) {
    designTabs = [];
    activeDesignTabId = '';
    newCard();
    return;
  }
  const wasActive = id === activeDesignTabId;
  designTabs.splice(index, 1);
  if (wasActive) {
    const next = designTabs[Math.min(index, designTabs.length - 1)];
    activeDesignTabId = '';
    switchDesignTab(next.id);
  } else renderDesignTabs();
}
function newCard() {
  const nextDesign = {
    designId: crypto.randomUUID(),
    name: 'New ID Card ' + (designTabs.length + 1),
    cardType: val('cardType') || 'portrait-hole',
    dataSource: 'universal',
    cardColor: '#ffffff',
    borderColor: '#98a2b3',
    cornerRadius: 12,
    typographyDefaultsVersion: TYPOGRAPHY_DEFAULTS_VERSION,
    elements: [],
    frontElements: [],
    backElements: []
  };
  addDesignTab(nextDesign, '');
}
function syncControls() {
  setVal('designName', design.name);
  setVal('cardType', design.cardType);
  setVal('cardColor', design.cardColor);
  setVal('borderColor', design.borderColor);
  setVal('cornerRadius', design.cornerRadius);
  document.getElementById('cornerValue').textContent = design.cornerRadius + 'px';
}
function allDesigns() {
  try {
    return JSON.parse(STUDIO_STORAGE.getItem(STORAGE_KEY) || '[]');
  } catch (e) {
    return [];
  }
}

function chooseDesignFile() {
  document.getElementById('openDesignFile').click();
}
function openDesignFromLocalAlbum(event) {
  const file = event.target.files[0];
  if (file) readDesignFile(file, null);
  event.target.value = '';
}
function designNameFromFile(fileName, fallback) {
  return String(fileName || '').replace(/\\.json$/i, '').trim() || String(fallback || '').trim() || 'Untitled ID Card';
}
function readDesignFile(file, fileHandle) {
  const status = document.getElementById('saveStatus');
  const reader = new FileReader();
  reader.onload = function (loadEvent) {
    try {
      const loaded = JSON.parse(loadEvent.target.result);
      if (!loaded || loaded.fileType !== 'ID_CARD_DESIGN' || !CARD_TYPES[loaded.cardType] || !Array.isArray(loaded.elements) && !Array.isArray(loaded.frontElements)) throw new Error('Choose a .json file saved by Design Studio. Image files and spreadsheets cannot be opened as card designs.');
      const embeddedLogo = loaded.logoData || '';
      const loadedDesign = ensureTwoSides(JSON.parse(JSON.stringify(loaded)));
      loadedDesign.name = designNameFromFile(file.name, loadedDesign.name);
      loadedDesign.dataSource = 'universal';
      delete loadedDesign.fileType;
      delete loadedDesign.schemaVersion;
      delete loadedDesign.savedAt;
      addDesignTab(loadedDesign, file.name || '');
      const drafts = allDesigns();
      const draftIndex = drafts.findIndex(item => item.name === loadedDesign.name);
      if (draftIndex < 0) drafts.push(JSON.parse(JSON.stringify(loadedDesign)));else drafts[draftIndex] = JSON.parse(JSON.stringify(loadedDesign));
      STUDIO_STORAGE.setItem(STORAGE_KEY, JSON.stringify(drafts));

      status.className = 'status header-status';
      status.textContent = 'Opened in a new preview tab: ' + file.name + '.';
    } catch (error) {
      status.className = 'status error header-status';
      status.textContent = 'Unable to open design: ' + (error.message || error);
    }
  };
  reader.onerror = function () {
    status.className = 'status error header-status';
    status.textContent = 'Unable to read the selected file.';
  };
  reader.readAsText(file);
}
async function saveDesignToLocalAlbum() {
  captureSelectedInspectorValues();
  const status = document.getElementById('saveStatus');
  const savingTabId = activeDesignTabId;
  const savingDesign = design;
  let saveWindow = null;
  try {
    ensureTwoSides(design);
    design.name = val('designName').trim() || 'Untitled ID Card';
    const albumDesign = JSON.parse(JSON.stringify(design));
    albumDesign.fileType = 'ID_CARD_DESIGN';
    albumDesign.schemaVersion = 5;
    albumDesign.logoData = logoData();
    albumDesign.savedAt = new Date().toISOString();
    const suggestedName = (design.name.replace(/[<>:"/\\\\|?*\\x00-\\x1f]/g, '').replace(/[. ]+$/g, '').trim() || 'ID Card Design') + '.json';
    saveWindow = window.open('', 'idCardSaveWindow', 'width=460,height=250');
    if (!saveWindow) throw new Error('Please allow pop-ups so the Save window can open.');
    saveWindow.document.title = 'Save ID Card Design';
    saveWindow.document.body.innerHTML = '<main style="max-width:390px;margin:36px auto;padding:22px;font-family:Segoe UI,Arial,sans-serif;text-align:center;color:#17233a"><h2 style="margin:0 0 10px">Save ID Card Design</h2><p id="saveHelp" style="margin:0 0 18px;color:#667085;line-height:1.5">Choose a folder and filename. The filename will also become the Design Name.</p><button id="chooseSaveLocation" style="display:none;width:100%;padding:12px;color:white;background:#2563eb;border:0;border-radius:8px;font-weight:700;cursor:pointer">Choose Save Location</button></main>';
    saveWindow.document.close();
    const help = saveWindow.document.getElementById('saveHelp');
    const chooseButton = saveWindow.document.getElementById('chooseSaveLocation');
    const completeSave = async function () {
      if (typeof saveWindow.showSaveFilePicker !== 'function') throw new Error('This browser does not support the Save file picker. Please use the latest Chrome or Microsoft Edge.');
      const handle = await saveWindow.showSaveFilePicker({
        suggestedName: suggestedName,
        types: [{
          description: 'ID Card Design',
          accept: {
            'application/json': ['.json']
          }
        }]
      });
      const savedFileName = handle.name || suggestedName;
      albumDesign.name = designNameFromFile(savedFileName, albumDesign.name);
      const blob = new Blob([JSON.stringify(albumDesign, null, 2)], {
        type: 'application/json;charset=utf-8'
      });
      const writable = await handle.createWritable();
      await writable.write(blob);
      await writable.close();
      savingDesign.name = albumDesign.name;
      const drafts = allDesigns();
      const draft = JSON.parse(JSON.stringify(savingDesign));
      const draftIndex = drafts.findIndex(item => item.name === draft.name);
      if (draftIndex < 0) drafts.push(draft);else drafts[draftIndex] = draft;
      STUDIO_STORAGE.setItem(STORAGE_KEY, JSON.stringify(drafts));

      const savingTab = designTabs.find(item => item.id === savingTabId);
      if (savingTab) {
        savingTab.fileName = savedFileName;
        savingTab.design.name = albumDesign.name;
      }
      if (activeDesignTabId === savingTabId) {
        currentDesignFileName = savedFileName;
        syncControls();

      }
      renderDesignTabs();
      status.className = 'status header-status';
      status.textContent = 'Design file saved: ' + savedFileName;
      if (window.markDesignSaved) {
        const savedState = JSON.parse(JSON.stringify(albumDesign));
        delete savedState.fileType;
        delete savedState.schemaVersion;
        delete savedState.savedAt;
        window.markDesignSaved(savingTabId, savedState);
      }
      saveWindow.close();
      render();
    };
    chooseButton.onclick = async function () {
      try {
        help.textContent = 'Choose a folder and filename in the file explorer.';
        await completeSave();
      } catch (error) {
        if (error && error.name === 'AbortError') {
          help.textContent = 'Save cancelled. You can try again.';
          return;
        }
        help.textContent = error.message || String(error);
        chooseButton.style.display = 'block';
      }
    };
    try {
      await completeSave();
    } catch (error) {
      if (error && error.name === 'AbortError') {
        saveWindow.close();
        status.className = 'status header-status';
        status.textContent = 'Save cancelled.';
        return;
      }
      help.textContent = 'Click below to open your device file explorer and choose where to save the card.';
      chooseButton.style.display = 'block';
      status.className = 'status header-status';
      status.textContent = 'Use the Save window to choose the file location.';
    }
  } catch (error) {
    if (saveWindow && !saveWindow.closed) saveWindow.close();
    status.className = 'status error header-status';
    status.textContent = 'Unable to save design: ' + (error.message || error);
  }
}

document.getElementById('designName').addEventListener('input', function () {
  design.name = this.value || 'New ID Card';
  document.getElementById('workspaceTitle').textContent = design.name;
  renderDesignTabs();
});
window.addEventListener('keydown', e => {
  const m = selected();
  if (!m || ['INPUT', 'SELECT'].includes(document.activeElement.tagName)) return;
  if (e.key === 'Delete' || e.key === 'Backspace') {
    e.preventDefault();
    deleteSelected();
    return;
  }
  const d = e.shiftKey ? 5 : 1;
  if (e.key === 'ArrowLeft') m.x -= d;else if (e.key === 'ArrowRight') m.x += d;else if (e.key === 'ArrowUp') m.y -= d;else if (e.key === 'ArrowDown') m.y += d;else return;
  e.preventDefault();
  clamp();
  render();
});
window.addEventListener('DOMContentLoaded', () => {
  buildFontSizeMenus();
  buildNewElementPicker();
  syncControls();

  const firstTab = {
    id: tabId(),
    design: design,
    activeSide: 'front',
    selectedId: null,
    fileName: ''
  };
  designTabs = [firstTab];
  activeDesignTabId = firstTab.id;
  renderDesignTabs();
  render();
});
</script>
<?!= include('ReliabilityClient'); ?>
<?!= include('DesignHistory'); ?>

<style>
button.designer-small-icon::before,
a.designer-small-icon::before,
.element-option-grid button.designer-small-icon::before {
  content:""!important;
  display:inline-block!important;
  width:14px!important;
  height:14px!important;
  margin:0 6px 0 0!important;
  padding:0!important;
  vertical-align:-2px;
  flex:0 0 14px;
  background:currentColor!important;
  border:0!important;
  border-radius:0!important;
  -webkit-mask:var(--designer-button-icon) center/contain no-repeat;
  mask:var(--designer-button-icon) center/contain no-repeat;
}
</style>
<script>
(function () {
  // Local monochrome SVGs inherit each button's text color.
  const paths = {
    add:'<path d="M12 5v14M5 12h14"/>',
    open:'<path d="M3 7V5h7l2 2h9v3M3 10h19l-3 10H3z"/>',
    save:'<path d="M4 3h13l4 4v14H3V3zM7 3v6h10V3M7 21v-8h10v8"/>',
    undo:'<path d="M9 5 3 11l6 6M3 11h11a6 6 0 0 1 6 6"/>',
    redo:'<path d="m15 5 6 6-6 6m6-6H10a6 6 0 0 0-6 6"/>',
    card:'<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 9h4M7 13h10"/>',
    back:'<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 9h10M7 12h10M7 15h6"/>',
    home:'<path d="m3 10 9-7 9 7M5 9v12h14V9M9 21v-8h6v8"/>',
    image:'<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8" cy="8" r="2"/><path d="m3 18 6-6 4 4 3-3 5 5"/>',
    person:'<circle cx="12" cy="7" r="4"/><path d="M4 21v-3a8 8 0 0 1 16 0v3"/>',
    text:'<path d="M4 5h16M12 5v14M8 19h8"/>',
    calendar:'<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M7 3v5M17 3v5M3 11h18M7 15h3M14 15h3"/>',
    phone:'<path d="m5 3 4 5-3 3c2 3 4 5 7 7l3-3 5 4c-1 4-5 3-9 1S3 11 3 7c0-2 0-3 2-4z"/>',
    mail:'<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 6 9 7 9-7"/>',
    location:'<path d="M19 9c0 6-7 12-7 12S5 15 5 9a7 7 0 0 1 14 0z"/><circle cx="12" cy="9" r="2"/>',
    signature:'<path d="m4 16 12-12 4 4L8 20H4zM14 6l4 4M13 21h8"/>',
    rectangle:'<rect x="3" y="5" width="18" height="14" rx="1"/>',
    circle:'<circle cx="12" cy="12" r="9"/>',
    line:'<path d="M3 12h18"/>',
    star:'<path d="m12 3 3 6 7 1-5 5 1 7-6-3-6 3 1-7-5-5 7-1z"/>',
    barcode:'<path d="M3 4v16M6 4v16M10 4v16M13 4v16M15 4v16M19 4v16M21 4v16"/>',
    qr:'<path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h3v3h4v4h-7v-3"/>',
    transport:'<rect x="4" y="3" width="16" height="17" rx="3"/><path d="M4 11h16M7 20v2M17 20v2M7 16h2M15 16h2"/>',
    rotate:'<path d="M4 9a8 8 0 1 1 0 6M4 3v6h6"/>',
    align:'<path d="M12 3v18M4 6h16M7 12h10M4 18h16"/>',
    border:'<rect x="3" y="3" width="18" height="18"/>'
  };
  const urls = {};
  Object.keys(paths).forEach(function(key) {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + paths[key] + '</svg>';
    urls[key] = 'url("data:image/svg+xml,' + encodeURIComponent(svg) + '")';
  });
  const elementIcons = {
    logo:'image',image:'image',signature:'signature',photo:'person',firstName:'person',lastName:'person',fullName:'person',middleName:'person',teacherName:'person',emergencyContact:'person',
    schoolYear:'calendar',issueDate:'calendar',expirationDate:'calendar',dateOfBirth:'calendar',phone:'phone',emergencyPhone:'phone',email:'mail',address:'location',campus:'home',buildingRoom:'home',homeroom:'home',
    divider:'line',rectangle:'rectangle',circle:'circle',icon:'star',barcodeNumber:'barcode',qrCode:'qr',transportation:'transport',idNumber:'card'
  };
  function decorate() {
    document.querySelectorAll('button, a.btn.home').forEach(function(button) {
      if (button.querySelector('svg') || button.classList.contains('rotate-handle') || button.classList.contains('resize-handle')) return;
      const label = button.textContent.trim();
      let key = null;
      if (button.closest('.element-option-grid')) {
        const type = Object.keys(LABELS).find(function(type) { return LABELS[type] === label; });
        if (type) key = elementIcons[type] || 'text';
      } else {
        const actions = {'New Card':'add','Open':'open','Save':'save','Undo':'undo','Redo':'redo','Front Side':'card','Back Side':'back','Replace Signature':'signature','Show Border':'border','Hide Border':'border'};
        key = actions[label];
        if (button.classList.contains('home')) key = 'home';
        if (button.closest('.rotation-presets')) key = 'rotate';
      }
      if (!key) return;
      button.classList.add('designer-small-icon');
      button.style.setProperty('--designer-button-icon', urls[key]);
    });
  }
  function start() {
    decorate();
    let queued = false;
    new MutationObserver(function() {
      if (queued) return;
      queued = true;
      requestAnimationFrame(function() { queued = false; decorate(); });
    }).observe(document.body, {childList:true,subtree:true,characterData:true});
  }
  window.addEventListener('DOMContentLoaded', start);
})();
</script>
<script>
// Build the current inspector once, in dependency order.
(function () {
function initializeInspectorPanels() {
    const inspector = document.getElementById('inspector');
    const groups = [
      ['settings', ['elementContentSettings', 'transportRules']],
      ['text', ['standardTypography', 'classTypography', '.inspector-box-style', 'orientationField']]
    ];
    for (const [key, ids] of groups) {
      const panel = document.createElement('div');
      panel.id = 'inspector-panel-' + key;
      panel.className = 'inspector-tab-panel';
      ids.forEach(id => {
        const node = id.startsWith('.') ? inspector.querySelector(id) : document.getElementById(id);
        if (node) panel.appendChild(node);
      });
      inspector.appendChild(panel);
    }
    // Independent grade styles stay available without showing both long forms at once.
    document.querySelectorAll('#classTypography > .grade-part').forEach((part, index) => {
      const section = document.createElement('details');
      section.open = index === 0;
      const summary = document.createElement('summary');
      summary.textContent = index === 0 ? 'Grade Label' : 'Grade Number';
      section.appendChild(summary);
      part.replaceWith(section);
      section.appendChild(part);
    });
  }

function setupCompactTextTools() {
    const toggles = [];
    const alignments = [];
    function addStyleButtons(ids, anchor) {
      const group = document.createElement('div');
      group.className = 'text-style-buttons';
      group.setAttribute('role', 'group');
      group.setAttribute('aria-label', 'Text style');
      ids.forEach(([id, letter, label, style]) => {
        const input = document.getElementById(id);
        const oldLabel = input.closest('label');
        oldLabel.hidden = true;
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'format-letter';
        button.textContent = letter;
        button.title = label;
        button.setAttribute('aria-label', label);
        button.dataset.style = style;
        button.onclick = () => {
          input.checked = !input.checked;
          updateSelectedFromInspector();
        };
        group.appendChild(button);
        toggles.push({input, button});
      });
      anchor.after(group);
    }
    const standardAnchor = document.getElementById('standardWeight').closest('.grade-control-grid');
    addStyleButtons([
      ['standardItalic', 'I', 'Italic', 'italic'],
      ['standardUnderline', 'U', 'Underline', 'underline'],
      ['standardStrike', 'S', 'Strikethrough', 'strike']
    ], standardAnchor);
    ['classLabel', 'classValue'].forEach(prefix => {
      addStyleButtons([[prefix + 'Italic', 'I', 'Italic', 'italic']], document.getElementById(prefix + 'Weight').closest('.grade-control-grid'));
    });
    // Keep related font styles together: toggles first, weight underneath.
    ['standard', 'classLabel', 'classValue'].forEach(prefix => {
      const weight = document.getElementById(prefix + 'Weight').closest('.grade-control');
      const colorRow = weight.parentElement;
      const buttons = colorRow.nextElementSibling;
      const section = document.createElement('section');
      section.className = 'font-style-group';
      section.setAttribute('aria-label', 'Font style');
      const heading = document.createElement('div');
      heading.className = 'font-style-heading';
      heading.textContent = 'Font Style';
      buttons.before(section);
      section.append(heading, buttons, weight);
      colorRow.classList.add('font-color-row');
      weight.classList.add('font-weight-row');
    });
    // Hide the empty checkbox row after replacing its controls.
    const oldRow = document.getElementById('standardItalic').closest('.grade-control-grid');
    oldRow.hidden = true;
    ['standardSize', 'classLabelSize', 'classValueSize'].forEach(id => {
      const select = document.getElementById(id);
      const wrapper = document.createElement('div');
      wrapper.className = 'size-stepper';
      select.before(wrapper);
      for (const step of [-1, 1]) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'size-step';
        button.textContent = step < 0 ? '−' : '+';
        button.title = step < 0 ? 'Decrease font size' : 'Increase font size';
        button.setAttribute('aria-label', button.title);
        button.onclick = () => {
          select.value = String(Math.max(FONT_SIZE_MIN, Math.min(FONT_SIZE_MAX, Number(select.value || 12) + step)));
          updateSelectedFromInspector();
        };
        if (step < 0) { wrapper.appendChild(button); wrapper.appendChild(select); }
        else wrapper.appendChild(button);
      }
    });
    ['standardHorizontalAlign', 'standardVerticalAlign', 'classLabelAlign', 'classLabelVerticalAlign', 'classValueAlign', 'classValueVerticalAlign'].forEach(id => {
      const select = document.getElementById(id);
      select.hidden = true;
      const group = document.createElement('div');
      group.className = 'alignment-buttons';
      group.setAttribute('role', 'group');
      group.setAttribute('aria-label', /Vertical/.test(id) ? 'Vertical alignment' : 'Horizontal alignment');
      Array.from(select.options).filter(option => option.value !== 'justify').forEach(option => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'align-choice';
        button.textContent = option.text;
        button.title = option.text + ' alignment';
        button.setAttribute('aria-label', button.title);
        button.onclick = () => { select.value = option.value; updateSelectedFromInspector(); };
        group.appendChild(button);
        alignments.push({select, button, value:option.value});
      });
      select.after(group);
    });
    window.syncCompactTextTools = function () {
      toggles.forEach(({input, button}) => button.setAttribute('aria-pressed', String(input.checked)));
      alignments.forEach(({select, button, value}) => button.setAttribute('aria-pressed', String(select.value === value)));
    };
    window.syncCompactTextTools();
  }

function polishFontTools() {
    const weightButtons = [];
    const colors = [];
    ['standard', 'classLabel', 'classValue'].forEach(prefix => {
      const weight = document.getElementById(prefix + 'Weight');
      const group = weight.closest('.font-style-group');
      const row = group.querySelector('.text-style-buttons');
      weight.closest('.font-weight-row').hidden = true;
      const color = document.getElementById(prefix + 'Color');
      const oldColorRow = color.closest('.font-color-row');
      const swatch = document.createElement('label');
      swatch.className = 'color-letter';
      swatch.title = 'Font color';
      const letter = document.createElement('span');
      letter.className = 'color-indicator';
      letter.textContent = 'A';
      letter.setAttribute('aria-hidden', 'true');
      swatch.append(letter, color);
      color.setAttribute('aria-label', 'Font color');
      row.prepend(swatch);
      oldColorRow.hidden = true;
      colors.push({swatch, color});
      const firstStyle = swatch.nextSibling;
      [['700','B','Bold'],['900','B','Extra bold']].forEach(([value, text, title]) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'format-letter';
        button.textContent = text;
        button.style.fontWeight = value;
        if (value === '900') button.style.fontFamily = 'Arial Black, Arial, sans-serif';
        button.title = title;
        button.setAttribute('aria-label', title);
        button.onclick = () => { weight.value = weight.value === value ? '400' : value; updateSelectedFromInspector(); };
        row.insertBefore(button, firstStyle);
        weightButtons.push({weight, button, value});
      });
    });
    document.querySelectorAll('.alignment-buttons').forEach(group => {
      const vertical = group.getAttribute('aria-label') === 'Vertical alignment';
      group.querySelectorAll('button').forEach(button => {
        const name = button.textContent.trim();
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('aria-hidden', 'true');
        function line(x1,y1,x2,y2) {
          const path = document.createElementNS('http://www.w3.org/2000/svg','path');
          path.setAttribute('d', 'M'+x1+' '+y1+'H'+x2);
          if(y1!==y2) path.setAttribute('d','M'+x1+' '+y1+'L'+x2+' '+y2);
          path.setAttribute('stroke','currentColor');path.setAttribute('stroke-width','1.8');
          svg.appendChild(path);
        }
        if (vertical) {
          const y = name === 'Top' ? 5 : name === 'Bottom' ? 13 : 9;
          line(3,2,21,2);line(3,22,21,22);
          line(6,y,18,y);line(8,y+3,16,y+3);line(6,y+6,18,y+6);
        } else {
          [18,12,18,10].forEach((width,index) => {
            const x = name === 'Right' ? 21-width : name === 'Center' ? (24-width)/2 : 3;
            line(x,5+index*4,x+width,5+index*4);
          });
        }
        button.replaceChildren(svg);
        button.title = (vertical ? 'Vertical: ' : 'Horizontal: ') + name;
        button.setAttribute('aria-label', button.title);
      });
    });
    const previousSync = window.syncCompactTextTools;
    window.syncCompactTextTools = function () {
      previousSync();
      weightButtons.forEach(({weight, button, value}) => button.setAttribute('aria-pressed',String(weight.value === value)));
      colors.forEach(({swatch,color}) => swatch.style.setProperty('--font-ink',color.value));
    };
    window.syncCompactTextTools();
  }

function groupAlignmentTools() {
    [['standardHorizontalAlign','standardVerticalAlign'],['classLabelAlign','classLabelVerticalAlign'],['classValueAlign','classValueVerticalAlign']].forEach(([horizontalId, verticalId]) => {
      const horizontal = document.getElementById(horizontalId);
      const vertical = document.getElementById(verticalId);
      const oldGrid = horizontal.closest('.grade-control-grid');
      const horizontalButtons = horizontal.nextElementSibling;
      const verticalButtons = vertical.nextElementSibling;
      const section = document.createElement('section');
      section.className = 'unified-alignment';
      const heading = document.createElement('h4');
      heading.textContent = 'Alignment';
      const row = document.createElement('div');
      row.className = 'alignment-icon-row';
      row.append(horizontalButtons, verticalButtons);
      section.append(heading, row);
      // Retain original selects for saved values and existing update handlers.
      const previousHeading = oldGrid.previousElementSibling;
      if (previousHeading && previousHeading.textContent.trim() === 'Alignment') previousHeading.hidden = true;
      oldGrid.before(section);
      oldGrid.hidden = true;
    });
  }

function arrangeTextEditor() {
    ['standard', 'classLabel', 'classValue'].forEach(prefix => {
      const font = document.getElementById(prefix + 'Font');
      const fontRow = font.closest('.grade-control-grid');
      const styleGroup = document.getElementById(prefix + 'Weight').closest('.font-style-group');
      const scope = prefix === 'standard' ? document.getElementById('standardTypography') : font.closest('.grade-part');
      const alignment = scope.querySelector('.unified-alignment');
      if (!fontRow || !styleGroup || !alignment) return;
      const layout = document.createElement('div');
      layout.className = 'text-editor-layout';
      fontRow.classList.add('font-picker-row');
      layout.append(fontRow, styleGroup, alignment);
      // Preserve dormant fields and their saved-value bindings, outside the visible layout.
      const storage = document.createElement('div');
      storage.hidden = true;
      while (scope.firstChild) storage.appendChild(scope.firstChild);
      scope.append(storage, layout);
      layout.querySelectorAll('.format-letter').forEach(button => {
        if (button.getAttribute('aria-label') === 'Extra bold') button.textContent = 'B+';
      });
    });
  }

function groupColorControls() {
    const box = document.querySelector('.inspector-box-style');
    const section = document.createElement('section');
    section.className = 'colors-border-group';
    const heading = document.createElement('h4');
    heading.textContent = 'Colors & Border';
    section.appendChild(heading);
    box.before(section);
    const textRows = [];
    [['standardColor','Text Color','text'],['classLabelColor','Grade Label Color','grade'],['classValueColor','Grade Number Color','grade'],['toolbarFillColor','Box Color','box']].forEach(([id,title,kind]) => {
      const input = document.getElementById(id);
      const oldSwatch = input.closest('.color-letter, .box-color-icon');
      const row = document.createElement('div');
      row.className = 'color-setting-row';
      const label = document.createElement('label');
      label.htmlFor = id;
      label.textContent = title;
      input.setAttribute('aria-label', title);
      input.title = title;
      row.append(label,input);
      section.appendChild(row);
      if(oldSwatch) oldSwatch.remove();
      if(kind !== 'box') textRows.push({row,kind});
    });
    const border = document.getElementById('toolbarBorder');
    const borderRow = document.createElement('div');
    borderRow.className = 'color-setting-row';
    const label = document.createElement('label');
    label.htmlFor = border.id;
    label.textContent = 'Border';
    borderRow.append(label,border);
    section.appendChild(borderRow);
    const thicknessRow = document.createElement('div');
    thicknessRow.className = 'color-setting-row';
    const thicknessLabel = document.createElement('label');
    thicknessLabel.htmlFor = 'elementBorderThickness';
    thicknessLabel.textContent = 'Border Line';
    const thickness = document.createElement('select');
    thickness.id = 'elementBorderThickness';
    thickness.className = 'input border-thickness';
    thickness.title = 'Border thickness in pixels';
    [0.5,1,2,3,4,5,6,8,10,12].forEach(value => {
      const option = document.createElement('option');
      option.value = String(value);
      option.textContent = value + ' px';
      thickness.appendChild(option);
    });
    thickness.onchange = () => {
      const model = selected();
      if (!model) return;
      model.borderWidth = Number(thickness.value);
      model.savedBorderWidth = model.borderWidth;
      render();
    };
    thicknessRow.append(thicknessLabel, thickness);
    section.appendChild(thicknessRow);
    const borderColorRow = document.createElement('div');
    borderColorRow.className = 'color-setting-row';
    const borderColorLabel = document.createElement('label');
    borderColorLabel.htmlFor = 'elementBorderColor';
    borderColorLabel.textContent = 'Border Color';
    const borderColor = document.createElement('input');
    borderColor.type = 'color';
    borderColor.id = 'elementBorderColor';
    borderColor.title = 'Border color';
    borderColor.oninput = () => setSelectedToolbarColor('borderColor', borderColor.value);
    borderColorRow.append(borderColorLabel, borderColor);
    section.appendChild(borderColorRow);
    const oldBoxRow = box.querySelector('.box-icon-row');
    if(oldBoxRow) oldBoxRow.remove();
    const previousSync = window.syncCompactTextTools;
    window.syncCompactTextTools = function () {
      previousSync();
      const model = selected();
      const grade = model && model.type === 'class';
      textRows.forEach(({row,kind}) => {
        row.hidden = !model || (kind === 'grade' ? !grade : grade || !textElement(model.type));
      });
      const on = !!model && Number(model.borderWidth || 0) > 0;
      if (model) {
        const width = Number(model.borderWidth || model.savedBorderWidth || 1);
        if (!Array.from(thickness.options).some(option => Number(option.value) === width)) {
          const option = document.createElement('option');
          option.value = String(width);
          option.textContent = width + ' px';
          thickness.appendChild(option);
        }
        thickness.value = String(width);
        borderColor.value = /^#[0-9a-f]{6}$/i.test(model.borderColor || '') ? model.borderColor : '#667085';
      }
      border.title = on ? 'Hide border' : 'Show border';
      border.setAttribute('aria-label',border.title);
    };
    window.syncCompactTextTools();
  }

function installBorderLinePicker() {
    const select = document.getElementById('elementBorderThickness');
    select.hidden = true;
    const picker = document.createElement('details');
    picker.className = 'border-line-picker';
    const summary = document.createElement('summary');
    summary.id = 'borderLinePickerButton';
    summary.setAttribute('aria-label', 'Choose border line thickness');
    summary.title = 'Choose a thinner or thicker border';
    const preview = document.createElement('span');
    preview.className = 'border-line-sample';
    preview.setAttribute('aria-hidden', 'true');
    summary.appendChild(preview);
    const options = document.createElement('div');
    options.className = 'border-line-options';
    options.setAttribute('role', 'group');
    options.setAttribute('aria-label', 'Border line thickness');
    picker.append(summary, options);
    select.after(picker);
    const label = select.parentElement.querySelector('label');
    if (label) label.htmlFor = summary.id;
    const choices = [];
    const names = ['Hairline', 'Thin', 'Light', 'Medium', 'Strong', 'Thick', 'Heavy', 'Very heavy', 'Extra heavy', 'Boldest'];
    Array.from(select.options).forEach((option,index) => {
      const value = Number(option.value);
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'border-line-option';
      button.title = (names[index] || 'Custom') + ' border (' + value + ' px)';
      button.setAttribute('aria-label',button.title);
      const line = document.createElement('span');
      line.className = 'border-line-sample';
      line.style.height = value + 'px';
      line.setAttribute('aria-hidden','true');
      button.appendChild(line);
      button.onclick = () => {
        select.value = option.value;
        select.dispatchEvent(new Event('change', {bubbles:true}));
        picker.open = false;
        summary.focus();
      };
      options.appendChild(button);
      choices.push({value,button});
    });
    picker.addEventListener('keydown', event => {
      if(event.key === 'Escape') { picker.open = false; summary.focus(); }
    });
    document.addEventListener('pointerdown', event => { if(!picker.contains(event.target)) picker.open=false; });
    const previousSync = window.syncCompactTextTools;
    let previousElement = null;
    window.syncCompactTextTools = function () {
      previousSync();
      const model = selected();
      if(model && model.id !== previousElement) picker.open=false;
      previousElement = model && model.id;
      const value = Number(select.value || 1);
      preview.style.height = Math.min(value,16) + 'px';
      choices.forEach(choice => choice.button.setAttribute('aria-pressed',String(choice.value === value)));
    };
    window.syncCompactTextTools();
  }

function installFontSizeDropdowns() {
    const sizes = [];
    for(let n=7;n<=20;n++) sizes.push(n);
    for(let n=22;n<=72;n+=2) sizes.push(n);
    ['standardSize','classLabelSize','classValueSize'].forEach(id => {
      const input=document.getElementById(id);
      input.removeAttribute('list');
      const combo=document.createElement('div');combo.className='font-size-combo';
      input.before(combo);combo.appendChild(input);
      const open=document.createElement('button');open.type='button';open.className='font-size-open';open.textContent='▾';
      open.setAttribute('aria-label','Show all font sizes');open.setAttribute('aria-expanded','false');
      const menu=document.createElement('div');menu.className='font-size-options';menu.hidden=true;menu.id=id+'Options';
      open.setAttribute('aria-controls',menu.id);
      function close(){menu.hidden=true;open.setAttribute('aria-expanded','false');}
      function show(){menu.hidden=false;menu.scrollTop=0;open.setAttribute('aria-expanded','true');}
      sizes.forEach(size=>{
        const button=document.createElement('button');button.type='button';button.className='font-size-choice';button.textContent=String(size);
        button.onclick=()=>{input.value=String(size);close();updateSelectedFromInspector();input.focus();};
        menu.appendChild(button);
      });
      open.onclick=()=>{if(menu.hidden)show();else close();};
      input.addEventListener('click',show);
      input.addEventListener('input',close);
      input.addEventListener('keydown',event=>{
        if(event.key==='ArrowDown'){event.preventDefault();show();menu.firstElementChild.focus();}
        if(event.key==='Escape')close();
      });
      menu.addEventListener('keydown',event=>{
        if(event.key==='Escape'){close();input.focus();}
        if(event.key==='ArrowDown'||event.key==='ArrowUp'){
          event.preventDefault();const next=event.key==='ArrowDown'?event.target.nextElementSibling:event.target.previousElementSibling;if(next)next.focus();
        }
      });
      document.addEventListener('pointerdown',event=>{if(!combo.contains(event.target))close();});
      combo.addEventListener('focusout',event=>{if(!combo.contains(event.relatedTarget))close();});
      combo.append(open,menu);
    });
  }
  function initializeInspector() {
    initializeInspectorPanels();
    setupCompactTextTools();
    polishFontTools();
    groupAlignmentTools();
    arrangeTextEditor();
    groupColorControls();
    installBorderLinePicker();
    installFontSizeDropdowns();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initializeInspector);
  else initializeInspector();
})();
</script>
</body>
</html>
`;

    case 'DesignHistory':
      return `<script>
(function () {
  const histories = new Map();
  let restoring = false;
  let timer = null;
  function snapshot(d) {
    function sort(v) {
      if (Array.isArray(v)) return v.map(sort);
      if (v && typeof v === 'object') {
        const out = {};
        Object.keys(v).sort().forEach(k => {
          if (['fileType', 'schemaVersion', 'savedAt'].includes(k) || k === 'logoData' && !v[k]) return;
          out[k] = sort(v[k]);
        });
        return out;
      }
      return v;
    }
    return JSON.stringify(sort(ensureTwoSides(JSON.parse(JSON.stringify(d)))));
  }
  function state(tab) {
    let h = histories.get(tab.id);
    if (!h) {
      const value = snapshot(tab.design);
      h = {
        undo: [value],
        redo: [],
        saved: value
      };
      histories.set(tab.id, h);
    }
    return h;
  }
  function observe() {
    if (window.__CLEARING_LOCAL_DATA || restoring || typeof designTabs === 'undefined') return;
    designTabs.forEach(tab => {
      const h = state(tab);
      const value = snapshot(tab.design);
      if (h.undo[h.undo.length - 1] !== value) {
        h.undo.push(value);
        if (h.undo.length > 50) h.undo.shift();
        h.redo = [];
      }
    });
    update();
  }
  function update() {
    const tab = designTabs.find(t => t.id === activeDesignTabId);
    if (!tab) return;
    const h = state(tab);
    document.getElementById('undoDesign').disabled = h.undo.length < 2;
    document.getElementById('redoDesign').disabled = !h.redo.length;
    document.querySelectorAll('.design-tab').forEach((node, i) => {
      const t = designTabs[i];
      if (t) node.title = (t.fileName || t.design.name) + (snapshot(t.design) !== state(t).saved ? ' — Unsaved changes' : '');
    });
  }
  function restore(direction) {
    observe();
    const tab = designTabs.find(t => t.id === activeDesignTabId);
    if (!tab) return;
    const h = state(tab);
    if (direction === 'undo') {
      if (h.undo.length < 2) return;
      h.redo.push(h.undo.pop());
    } else {
      if (!h.redo.length) return;
      h.undo.push(h.redo.pop());
    }
    restoring = true;
    design = ensureTwoSides(JSON.parse(h.undo[h.undo.length - 1]));
    tab.design = design;
    selectedId = null;
    syncControls();
    renderDesignTabs();
    render();
    restoring = false;
    update();
  }
  window.markDesignSaved = function (tabId, savedSnapshot) {
    const tab = designTabs.find(t => t.id === tabId);
    if (!tab) return;
    const h = state(tab);
    h.saved = snapshot(savedSnapshot);
    observe();
    if (tab.closeAfterSave && snapshot(tab.design) === h.saved) {
      tab.closeAfterSave = false;
      reallyClose(tabId);
      observe();
    }
  };
  const reallyClose = closeDesignTab;
  closeDesignTab = function (id) {
    observe();
    const tab = designTabs.find(t => t.id === id);
    if (!tab) return;
    if (snapshot(tab.design) === state(tab).saved) {
      reallyClose(id);
      observe();
      return;
    }
    const dialog = document.createElement('dialog');
    dialog.className = 'reliability-dialog';
    dialog.innerHTML = '<h2>Unsaved Changes</h2><p>Save this card design before closing its tab?</p><button>Save</button><button>Discard</button><button>Cancel</button>';
    document.body.append(dialog);
    const buttons = dialog.querySelectorAll('button');
    buttons[0].onclick = () => {
      switchDesignTab(id);
      tab.closeAfterSave = true;
      dialog.close();
      saveDesignToLocalAlbum();
    };
    buttons[1].onclick = () => {
      dialog.close();
      reallyClose(id);
      observe();
    };
    buttons[2].onclick = () => dialog.close();
    dialog.addEventListener('close', () => dialog.remove());
    dialog.showModal();
  };
  const oldRender = render;
  render = function () {
    oldRender();
    if (!restoring) {
      clearTimeout(timer);
      timer = setTimeout(observe, 250);
    }
  };
  const oldAdd = addDesignTab;
  addDesignTab = function (d, file) {
    oldAdd(d, file);
    state(designTabs.find(t => t.id === activeDesignTabId));
    observe();
  };
  window.addEventListener('beforeunload', event => {
    if (window.__CLEARING_LOCAL_DATA) return;
    observe();
    if (designTabs.some(t => snapshot(t.design) !== state(t).saved)) {
      event.preventDefault();
      event.returnValue = '';
    }
  });
  ['input', 'change', 'click', 'pointerup', 'keyup'].forEach(type => document.addEventListener(type, () => {
    clearTimeout(timer);
    timer = setTimeout(observe, type === 'input' ? 300 : 0);
  }));
  document.addEventListener('keydown', event => {
    if (!(event.ctrlKey || event.metaKey) || event.altKey) return;
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) return;
    if (event.key.toLowerCase() === 'z') {
      event.preventDefault();
      restore(event.shiftKey ? 'redo' : 'undo');
    } else if (event.key.toLowerCase() === 'y') {
      event.preventDefault();
      restore('redo');
    }
  });
  window.addEventListener('DOMContentLoaded', () => {
    const bar = document.getElementById('designHistoryActions');
    if (!bar) return;
    bar.innerHTML = '<button id="undoDesign" class="btn" type="button" title="Undo the last design change">Undo</button><button id="redoDesign" class="btn" type="button" title="Redo the last undone change">Redo</button>';
    document.getElementById('undoDesign').onclick = () => restore('undo');
    document.getElementById('redoDesign').onclick = () => restore('redo');
    designTabs.forEach(state);
    update();
  });
})();
</script>
`;

    case 'DesignRuntime':
      return `<script src="https://cdn.jsdelivr.net/npm/jsbarcode@3.11.5/dist/JsBarcode.all.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js"></script>
<style>
.album-design-card {
  position:relative;
  overflow:hidden;
  background:#fff;
  border:1px solid #98a2b3;
  box-shadow:0 12px 28px rgba(23,32,51,.16);
  box-sizing:border-box
}
.album-design-card * {
  box-sizing:border-box
}
.album-lanyard {
  width:56px;
  height:12px;
  position:absolute;
  z-index:999;
  top:7px;
  left:50%;
  transform:translateX(-50%);
  border:1px dashed #98a2b3;
  border-radius:8px;
  pointer-events:none
}
.album-element {
  position:absolute;
  min-width:1px;
  min-height:1px;
  display:flex;
  align-items:center;
  justify-content:center;
  overflow:visible;
  transform-origin:center
}
.album-element-text {
  width:100%;
  min-width:0;
  max-width:100%;
  max-height:100%;
  display:block;
  padding:1px 2px;
  line-height:1.08;
  white-space:normal;
  overflow-wrap:anywhere;
  word-break:normal;
  overflow:hidden
}
.album-element-text.justify,.album-element-text.auto-justified {
  text-align:justify;
  text-align-last:auto;
  text-justify:inter-word
}
.album-element img {
  width:100%;
  height:100%;
  display:block;
  object-fit:contain
}
.album-element.album-photo {
  overflow:hidden;
  border:1px dashed #7b8ba4;
  border-radius:7px;
  background:#f3f6fa
}
.album-element.album-photo img {
  object-fit:cover
}
.album-photo-placeholder {
  width:100%;
  height:100%;
  display:grid;
  place-items:center;
  color:#667085;
  background:#f3f6fa;
  font-size:10px;
  font-weight:750
}
.album-barcode {
  width:100%;
  height:100%;
  display:block
}
.album-qr {
  width:100%;
  height:100%;
  display:grid;
  place-items:center;
  background:#fff
}
.album-qr svg {
  width:100%;
  height:100%;
  display:block
}
.album-grade {
  width:100%;
  height:100%;
  display:grid;
  grid-template-columns:minmax(0,1fr) minmax(0,1fr);
  gap:4px
}
.album-grade span {
  min-width:0;
  height:100%;
  display:flex;
  overflow:hidden
}
.album-grade.grade-pair-aligned {
  grid-auto-rows:max-content;
  align-items:baseline
}
.album-grade.grade-pair-aligned span {
  height:auto;
  align-items:baseline!important
}
.album-transport {
  width:100%;
  height:100%;
  display:flex;
  align-items:center;
  justify-content:center
}
.album-transport svg {
  width:90%;
  height:90%
}
.column-mapping-modal {
  position:fixed;
  inset:0;
  z-index:100000;
  padding:20px;
  display:grid;
  place-items:center;
  background:rgba(15,23,42,.68);
  font-family:"Segoe UI",Arial,sans-serif;
  color:#172033
}
.column-mapping-dialog {
  width:min(920px,100%);
  max-height:calc(100vh - 40px);
  display:flex;
  flex-direction:column;
  overflow:hidden;
  background:#fff;
  border:1px solid #d0d5dd;
  border-radius:16px;
  box-shadow:0 24px 70px rgba(15,23,42,.32)
}
.column-mapping-head {
  padding:20px 22px 15px;
  border-bottom:1px solid #e4e7ec
}
.column-mapping-head h2 {
  margin:0 0 5px;
  font-size:21px
}
.column-mapping-head p {
  margin:0;
  color:#667085;
  font-size:12px;
  line-height:1.5
}
.column-mapping-summary {
  padding:10px 22px;
  color:#344054;
  background:#f8fafc;
  border-bottom:1px solid #e4e7ec;
  font-size:12px;
  font-weight:750
}
.column-mapping-table-wrap {
  overflow:auto
}
.column-mapping-table {
  width:100%;
  border-collapse:collapse
}
.column-mapping-table th,.column-mapping-table td {
  padding:10px 12px;
  border-bottom:1px solid #eaecf0;
  text-align:left;
  vertical-align:middle
}
.column-mapping-table th {
  position:sticky;
  top:0;
  z-index:1;
  color:#475467;
  background:#f8fafc;
  font-size:10px;
  letter-spacing:.06em;
  text-transform:uppercase
}
.column-mapping-element strong {
  display:block;
  font-size:13px
}
.column-mapping-element span {
  display:block;
  margin-top:2px;
  color:#667085;
  font-size:10px
}
.column-mapping-select {
  width:100%;
  min-width:190px;
  padding:8px 9px;
  background:#fff;
  border:1px solid #cbd5e1;
  border-radius:7px;
  font:12px inherit
}
.column-mapping-sample {
  max-width:260px;
  color:#475467;
  font-size:11px;
  overflow-wrap:anywhere
}
.column-mapping-state {
  display:inline-block;
  padding:4px 7px;
  border-radius:999px;
  font-size:10px;
  font-weight:800
}
.column-mapping-state.mapped {
  color:#067647;
  background:#ecfdf3
}
.column-mapping-state.missing {
  color:#b54708;
  background:#fffaeb
}
.column-mapping-actions {
  padding:14px 22px;
  display:flex;
  flex-wrap:wrap;
  justify-content:flex-end;
  gap:9px;
  background:#fff
}
.column-mapping-actions button {
  min-height:39px;
  padding:8px 15px;
  border:0;
  border-radius:8px;
  font:750 12px "Segoe UI",Arial,sans-serif;
  cursor:pointer
}
.column-mapping-auto {
  margin-right:auto;
  color:#1748b5;
  background:#eaf2ff
}
.column-mapping-cancel {
  color:#344054;
  background:#edf0f4
}
.column-mapping-save {
  color:#fff;
  background:#185adb
}
@media(max-width:680px) {
  .column-mapping-modal {
    padding:8px
  }
  .column-mapping-dialog {
    max-height:calc(100vh - 16px)
  }
  .column-mapping-table th:nth-child(3),.column-mapping-table td:nth-child(3) {
    display:none
  }
  .column-mapping-actions {
    padding:12px
  }
  .column-mapping-auto {
    margin-right:0
  }
}
@media print {
  @page {
    size:auto;
    margin:0
  }
  .album-design-card {
    margin:0!important;
    padding:0!important;
    border:0!important;
    border-radius:0!important;
    box-shadow:none!important;
    page-break-after:always;
    break-after:page;
    -webkit-print-color-adjust:exact!important;
    print-color-adjust:exact!important
  }
  .album-design-card:last-child {
    page-break-after:auto;
    break-after:auto
  }
  .album-design-card.album-portrait {
    width:53.98mm!important;
    height:85.60mm!important
  }
  .album-design-card.album-landscape {
    width:85.60mm!important;
    height:53.98mm!important
  }
  .album-lanyard {
    border-color:transparent!important
  }
}
</style>
<script>
window.CardDesignRuntime = function () {
  const SPECS = {
    'portrait-hole': {
      width: 204,
      height: 324,
      hole: true
    },
    'landscape-hole': {
      width: 324,
      height: 204,
      hole: true
    },
    'portrait-plain': {
      width: 204,
      height: 324,
      hole: false
    },
    'landscape-plain': {
      width: 324,
      height: 204,
      hole: false
    }
  };
  const TYPOGRAPHY_DEFAULTS_VERSION = 1;
  const FONT_SIZE_MIN = 1;
  const FONT_SIZE_MAX = 72;
  const renderContexts = new WeakMap();
  const DATA_LABELS = {
    emergencyPhone: 'Emergency Phone',
    homeroom: 'Homeroom / Advisory',
    teacherName: 'Teacher Name',
    buildingRoom: 'Building / Room',
    text: 'Text',
    firstName: 'First Name',
    lastName: 'Last Name',
    fullName: 'Full Name',
    idNumber: 'ID Number',
    barcodeNumber: 'Barcode Number',
    qrCode: 'QR Code',
    title: 'Title',
    class: 'Grade Level',
    transportation: 'Transportation',
    middleName: 'Middle Name',
    department: 'Department',
    email: 'E-Mail',
    phone: 'Phone Number',
    address: 'Address',
    dateOfBirth: 'Date of Birth',
    issueDate: 'Issue Date',
    expirationDate: 'Expiration Date',
    emergencyContact: 'Emergency Contact',
    bloodType: 'Blood Type',
    campus: 'Campus Name'
  };
  const DESIGN_ONLY_TYPES = ['schoolYear', 'logo', 'image', 'photo', 'signature', 'instructions', 'divider', 'rectangle', 'circle', 'icon'];
  function sideElements(design, side) {
    if (side === 'back') return Array.isArray(design.backElements) ? design.backElements : [];
    return Array.isArray(design.frontElements) ? design.frontElements : Array.isArray(design.elements) ? design.elements : [];
  }
  function normalized(value) {
    return String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, ' ');
  }
  function aliases(value) {
    return String(value || '').split(',').map(normalized).filter(Boolean);
  }
  function transportName(value, model) {
    const target = normalized(value);
    const rules = model || {};
    if (!target || aliases(rules.transportNoneValues || 'None, N/A, No Transportation').includes(target)) return 'None';
    if (aliases(rules.transportBusValues || 'Bus, School Bus').includes(target)) return 'Bus';
    if (aliases(rules.transportWalkValues || 'Walk, Walking, Walker').includes(target)) return 'Walking';
    if (aliases(rules.transportPickupValues || 'Pick Up, Pickup, Car, Car Rider, Parent Pickup').includes(target)) return 'Pick Up';
    return 'None';
  }
  function mappedColumnIndex(model, options) {
    if (!model || DESIGN_ONLY_TYPES.indexOf(model.type) !== -1) return -1;
    if (options && Object.prototype.hasOwnProperty.call(options, 'columnMap')) {
      const map = options.columnMap && typeof options.columnMap === 'object' ? options.columnMap : {};
      const value = map[model.id];
      const index = value !== undefined && value !== null && value !== '' ? Number(value) : -1;
      return Number.isInteger(index) && index >= 0 ? index : -1;
    }
    if (Object.prototype.hasOwnProperty.call(model, 'runtimeColumnIndex')) {
      const runtime = model.runtimeColumnIndex !== undefined && model.runtimeColumnIndex !== null && model.runtimeColumnIndex !== '' ? Number(model.runtimeColumnIndex) : -1;
      return Number.isInteger(runtime) && runtime >= 0 ? runtime : -1;
    }
    const legacy = model.columnIndex !== undefined && model.columnIndex !== null && model.columnIndex !== '' ? Number(model.columnIndex) : -1;
    return Number.isInteger(legacy) && legacy >= 0 ? legacy : -1;
  }
  function hasDataLink(model, options) {
    return mappedColumnIndex(model, options) >= 0;
  }
  function boundValue(model, record, options) {
    const index = mappedColumnIndex(model, options);
    if (index < 0) return null;
    record = record || {};
    const row = Array.isArray(record._row) ? record._row : [];
    return index < row.length ? String(row[index] == null ? '' : row[index]) : '';
  }
  function field(type, record, options, model) {
    options = options || {};
    if (['schoolYear', 'instructions', 'icon'].includes(type)) return model && model.text || '';
    if (options.emptyPreview) return '';
    const bound = boundValue(model, record, options);
    if (bound === null) return '';
    if (type === 'idNumber') return bound ? 'ID #: ' + bound : '';
    if (type === 'transportation') return transportName(bound, model);
    return bound;
  }
  function drawQr(host, value) {
    if (!host) return;
    if (typeof qrcode !== 'function') {
      host.textContent = 'QR';
      return;
    }
    try {
      const qr = qrcode(0, 'M');
      qr.addData(value || ' ');
      qr.make();
      host.innerHTML = qr.createSvgTag({
        cellSize: 2,
        margin: 0,
        scalable: true
      });
      const svg = host.querySelector('svg');
      if (svg) {
        svg.setAttribute('width', '100%');
        svg.setAttribute('height', '100%');
        svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
      }
    } catch (error) {
      host.textContent = 'Invalid QR';
    }
  }
  function transportSvg(type, model) {
    const a = 'viewBox="0 0 24 24" role="img" aria-label="' + type + '"';
    if (type === 'Bus') return '<div class="album-transport" title="Bus"><svg ' + a + ' fill="#e67e22"><path d="M4 16c0 1.1.9 2 2 2h1v1a1 1 0 0 0 2 0v-1h6v1a1 1 0 0 0 2 0v-1h1c1.1 0 2-.9 2-2V6c0-3.5-3.6-4-8-4S4 2.5 4 6v10zm3 1a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3zm10 0a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3zm1-6H6V6h12v5z"/></svg></div>';
    if (type === 'Walking') {
      if (model && model.transportWalkingIconType === 'custom' && model.transportWalkingIconData) return '<div class="album-transport" title="Walking"><img src="' + model.transportWalkingIconData + '" alt="Walking"></div>';
      return '<div class="album-transport" title="Walking"><svg ' + a + ' fill="#27ae60"><circle cx="12" cy="3.5" r="2"/><path d="M10.2 7.1c.8-.7 2.8-.7 3.6 0l1.6 1.7c.8.8 1.8 1.3 3 1.4l-.2 2c-1.7-.1-3.2-.8-4.4-2l-.3-.3-.5 3 2.3 2.4V22h-2.2v-5.7l-2-1.9-1 3.2L7.7 22H5.2l2.9-5.4 1.1-5.8-1.4 1.4c-.8.8-1.8 1.3-2.9 1.5l-.4-2c.8-.2 1.4-.5 2-1.1l3.7-3.5z"/></svg></div>';
    }
    if (type === 'Pick Up') return '<div class="album-transport" title="Pick Up"><svg ' + a + ' fill="#185adb"><path d="M5 11l1.5-4.5h11L19 11H5zm14.5 1h-15C3.67 12 3 12.67 3 13.5V18h2v1a1 1 0 0 0 2 0v-1h10v1a1 1 0 0 0 2 0v-1h2v-4.5c0-.83-.67-1.5-1.5-1.5zM6.5 16a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3zm11 0a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3z"/></svg></div>';
    return '';
  }
  function transportDisplay(type) {
    if (type === 'Bus') return '<div class="album-transport" title="Bus"><svg viewBox="0 0 24 24" role="img" aria-label="Bus"><text x="12" y="19" text-anchor="middle" font-size="20">🚌</text></svg></div>';
    if (type === 'Pick Up') return '<div class="album-transport" title="Pick Up"><svg viewBox="0 0 24 24" role="img" aria-label="Pick Up"><text x="12" y="19" text-anchor="middle" font-size="20">🚗</text></svg></div>';
    return transportSvg(type, {});
  }
  function clampFontSize(value, fallback) {
    const number = Number(value);
    return Math.max(FONT_SIZE_MIN, Math.min(FONT_SIZE_MAX, Number.isFinite(number) ? number : fallback || 12));
  }
  function applyTypographyDefaults(design) {
    if (!design) return design;
    sideElements(design, 'front').concat(sideElements(design, 'back')).forEach(function (model) {
      if (!model) return;
      if (model.type === 'class') {
        model.classLabelSize = clampFontSize(model.classLabelSize, 12);
        model.classValueSize = clampFontSize(model.classValueSize, 12);
      } else if (['signature', 'divider', 'rectangle', 'circle', 'logo', 'image', 'photo', 'barcodeNumber', 'qrCode', 'transportation'].indexOf(model.type) === -1) {
        model.fontSize = clampFontSize(model.fontSize, 12);
      }
    });
    design.typographyDefaultsVersion = TYPOGRAPHY_DEFAULTS_VERSION;
    return design;
  }
  function fitTextToBox(host, text, maxFontSize, autoJustify, preferredAlign) {
  if (!host || !text || !String(text.textContent || '').trim()) return;
  // Store the user's maximum, never the temporarily reduced display size.
  text.dataset.fitMaxFontSize = String(maxFontSize || 12);
  text.dataset.fitAlign = preferredAlign || '';
  text.dataset.fitSelf = host === text ? 'true' : 'false';
  const applyFit = function () {
    const max = Math.max(1, Number(maxFontSize) || 12);
    const availableWidth = host.clientWidth;
    // Grade segments size themselves to their text. Their current height must
    // never become the next fit limit, especially during repeated print passes.
    const gradeBox = host === text && host.parentElement && host.parentElement.classList.contains('album-grade') ? host.parentElement : null;
    const availableHeight = gradeBox ? gradeBox.clientHeight : host.clientHeight;
    if (availableWidth < 1 || availableHeight < 1) return;
    text.style.maxWidth = '100%';
    text.style.maxHeight = 'none';
    text.style.overflow = 'visible';
    text.style.flexShrink = '0';
    text.style.boxSizing = 'border-box';
    text.style.letterSpacing = 'normal';
    text.style.wordSpacing = 'normal';
    text.style.overflowWrap = 'anywhere';
    text.style.wordBreak = 'normal';
    text.style.textAlign = preferredAlign || text.style.textAlign || 'center';
    text.style.textAlignLast = 'auto';
    text.style.textJustify = 'inter-word';
    text.classList.remove('auto-justified');
    // Leave a small margin for browser rounding and glyph descenders.
    const heightLimit = Math.max(1, availableHeight - (gradeBox ? 0 : 1));
    // A full-width text block has scrollWidth == host width even without overflow.
    const fitsContent = function () {
      return text.scrollWidth <= availableWidth && text.scrollHeight <= heightLimit;
    };
    text.style.fontSize = max + 'px';
    if (!fitsContent()) {
      let low = 0.1;
      let high = max;
      let best = low;
      for (let pass = 0; pass < 18; pass++) {
        const candidate = (low + high) / 2;
        text.style.fontSize = candidate + 'px';
        if (fitsContent()) { best = candidate; low = candidate; }
        else high = candidate;
      }
      text.style.fontSize = Math.max(0.1, Math.floor(best * 100) / 100) + 'px';
    }
    // The font size fits the entire content; do not crop the final text line.
    text.style.maxHeight = 'none';
    text.style.overflow = 'visible';
  };
  applyFit();
  if (typeof requestAnimationFrame === 'function') requestAnimationFrame(function () {
    if (text.isConnected) applyFit();
  });
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(function () {
    if (text.isConnected) applyFit();
  });
}
  function fitDataElement(node, model, options) {
    if (!node || !model || ['signature', 'divider', 'rectangle', 'circle', 'logo', 'image', 'photo', 'barcodeNumber', 'qrCode', 'transportation'].indexOf(model.type) !== -1) return;
    if (model.type === 'class') {
      const segments = node.querySelectorAll('.album-grade span');
      fitTextToBox(segments[0], segments[0], Number(model.classLabelSize || 12), false, '');
      fitTextToBox(segments[1], segments[1], Number(model.classValueSize || 12), false, '');
      return;
    }
    fitTextToBox(node, node.querySelector('.album-element-text'), Number(model.fontSize || 12), hasDataLink(model, options), model.align || 'center');
  }
  function render(container, design, record, options) {
    if (!container || !design) return null;
    applyTypographyDefaults(design);
    record = record || {};
    options = options || {};
    if (window.StudioReliability && StudioReliability.photoStates.get(String(record.recordKey || '')) === 'failed') options.photoError = true;
    const side = options.side === 'back' ? 'back' : 'front';
    const spec = SPECS[design.cardType] || SPECS['portrait-hole'];
    renderContexts.set(container, {
      design: design,
      record: record,
      options: Object.assign({}, options)
    });
    setPrintPageSize(spec);
    container.innerHTML = '';
    const card = document.createElement('div');
    card.className = 'album-design-card ' + (spec.width > spec.height ? 'album-landscape' : 'album-portrait');
    card.dataset.recordId = String(options.recordId || record.recordKey || '');
    card.dataset.cardSide = side;
    Object.assign(card.style, {
      width: spec.width + 'px',
      height: spec.height + 'px',
      background: design.cardColor || '#fff',
      borderColor: design.borderColor || '#98a2b3',
      borderRadius: Number(design.cornerRadius || 0) + 'px'
    });
    if (spec.hole) {
      const hole = document.createElement('div');
      hole.className = 'album-lanyard';
      card.appendChild(hole);
    }
    container.appendChild(card);
    sideElements(design, side).slice().sort((a, b) => (a.z || 0) - (b.z || 0)).forEach(function (model) {
      const node = document.createElement('div');
      node.className = 'album-element' + (model.type === 'photo' ? ' album-photo' : '');
      Object.assign(node.style, {
        left: Number(model.x || 0) + 'px',
        top: Number(model.y || 0) + 'px',
        width: Number(model.w || 20) + 'px',
        height: Number(model.h || 18) + 'px',
        zIndex: String(model.z || 1),
        color: model.color || '#111827',
        backgroundColor: model.backgroundColor || 'transparent',
        borderColor: model.borderColor || '#667085',
        borderStyle: Number(model.borderWidth || 0) > 0 ? 'solid' : 'none',
        borderWidth: Number(model.borderWidth || 0) + 'px',
        opacity: String(model.opacity === undefined ? 1 : model.opacity),
        fontSize: Number(model.fontSize || 12) + 'px',
        fontWeight: model.fontWeight || '400',
        fontFamily: model.fontFamily || 'Segoe UI, Arial, sans-serif',
        fontStyle: model.italic ? 'italic' : 'normal',
        textDecoration: [model.underline ? 'underline' : '', model.strike ? 'line-through' : ''].filter(Boolean).join(' ') || 'none',
        textAlign: model.align || 'center',
        justifyContent: model.align === 'left' ? 'flex-start' : model.align === 'right' ? 'flex-end' : 'center',
        alignItems: model.verticalAlign || 'center',
        transform: 'rotate(' + Number(model.rotation || 0) + 'deg)'
      });
      if (['divider', 'rectangle', 'circle'].includes(model.type)) {
        node.style.borderRadius = model.type === 'circle' ? '50%' : '0';
      } else if (model.type === 'logo') {
        const src = model.imageData || design.logoData || '';
        if (src) {
          const image = document.createElement('img');
          image.src = src;
          image.alt = 'Card logo';
          node.appendChild(image);
        }
      } else if (model.type === 'image' || model.type === 'signature') {
        if (model.imageData) {
          const image = document.createElement('img');
          image.src = model.imageData;
          image.alt = model.type === 'signature' ? 'Signature' : 'Card image';
          node.appendChild(image);
        }
      } else if (model.type === 'photo') {
        if (options.photoData) {
          const image = document.createElement('img');
          image.src = options.photoData;
          image.alt = 'ID photo';
          node.appendChild(image);
        } else {
          const placeholder = document.createElement('div');
          placeholder.className = 'album-photo-placeholder';
          placeholder.textContent = options.emptyPreview ? '' : options.photoLoading ? 'LOADING...' : options.photoError ? 'PHOTO ERROR' : 'NO PHOTO';
          node.appendChild(placeholder);
        }
      } else if (model.type === 'barcodeNumber') {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.classList.add('album-barcode');
        node.appendChild(svg);
        if (typeof JsBarcode === 'function' && field('barcodeNumber', record, options, model)) {
          try {
            JsBarcode(svg, field('barcodeNumber', record, options, model), {
              format: 'CODE128',
              width: 1.25,
              height: Math.max(18, Number(model.h || 40)),
              displayValue: false,
              margin: 0
            });
          } catch (error) {}
        }
      } else if (model.type === 'qrCode') {
        const qr = document.createElement('div');
        qr.className = 'album-qr';
        node.appendChild(qr);
        const qrValue = field('qrCode', record, options, model);
        if (qrValue) drawQr(qr, qrValue);
      } else if (model.type === 'class') {
        const box = document.createElement('div');
        box.className = 'album-grade';
        const label = document.createElement('span');
        const value = document.createElement('span');
        label.textContent = !options.emptyPreview && hasDataLink(model, options) ? 'Grade' : '';
        value.textContent = field('class', record, options, model);
        const labelVertical = model.classLabelVerticalAlign || 'center';
        const valueVertical = model.classValueVerticalAlign || 'center';
        Object.assign(label.style, {
          fontFamily: model.classLabelFont || 'Segoe UI, Arial, sans-serif',
          fontSize: Number(model.classLabelSize || 12) + 'px',
          color: model.classLabelColor || '#185adb',
          fontWeight: model.classLabelWeight || '700',
          fontStyle: model.classLabelItalic ? 'italic' : 'normal',
          justifyContent: model.classLabelAlign || 'flex-end',
          alignItems: labelVertical
        });
        Object.assign(value.style, {
          fontFamily: model.classValueFont || 'Segoe UI, Arial, sans-serif',
          fontSize: Number(model.classValueSize || 12) + 'px',
          color: model.classValueColor || '#111827',
          fontWeight: model.classValueWeight || '900',
          fontStyle: model.classValueItalic ? 'italic' : 'normal',
          justifyContent: model.classValueAlign || 'flex-start',
          alignItems: valueVertical
        });
        if (labelVertical === valueVertical) {
          box.classList.add('grade-pair-aligned');
          Object.assign(box.style, {
            gridAutoRows: 'max-content',
            alignItems: 'baseline',
            alignContent: labelVertical === 'flex-start' ? 'start' : labelVertical === 'flex-end' ? 'end' : 'center'
          });
          Object.assign(label.style, {
            height: 'auto',
            alignItems: 'baseline'
          });
          Object.assign(value.style, {
            height: 'auto',
            alignItems: 'baseline'
          });
        }
        box.append(label, value);
        node.appendChild(box);
      } else if (model.type === 'transportation') node.innerHTML = transportDisplay(field('transportation', record, options, model));else {
        const text = document.createElement('span');
        text.className = 'album-element-text' + (model.align === 'justify' ? ' justify' : '');
        text.textContent = field(model.type, record, options, model);
        Object.assign(text.style, {
          width: '100%',
          maxHeight: '100%',
          padding: '1px 2px',
          lineHeight: '1.08',
          whiteSpace: model.type === 'instructions' ? 'pre-wrap' : 'normal',
          overflowWrap: 'anywhere',
          overflow: 'hidden',
          textAlign: model.align || 'center',
          textAlignLast: 'auto'
        });
        node.appendChild(text);
      }
      card.appendChild(node);
      fitDataElement(node, model, options);
    });
    return card;
  }
  function setPrintPageSize(spec) {
    let style = document.getElementById('id-card-print-page-size');
    if (!style) {
      style = document.createElement('style');
      style.id = 'id-card-print-page-size';
      document.head.appendChild(style);
    }
    style.textContent = '@media print{@page{size:' + (spec.width > spec.height ? '85.60mm 53.98mm' : '53.98mm 85.60mm') + ';margin:0}}';
  }
  function linkedValueForType(design, record, type, options) {
    const model = sideElements(design, 'front').concat(sideElements(design, 'back')).find(function (item) {
      return item && item.type === type && hasDataLink(item, options);
    });
    const value = boundValue(model, record, options);
    return value === null ? '' : String(value).trim();
  }
  function getPhotoKey(design, record) {
    if (!sideElements(design, 'front').concat(sideElements(design, 'back')).some(model => model.type === 'photo')) return '';
    return String(record && record.recordKey || '');
  }
  function linkedFormFields(design, headers, row, excludedIndexes, columnMap) {
    if (!design) return [];
    headers = Array.isArray(headers) ? headers : [];
    row = Array.isArray(row) ? row : [];
    const excluded = Array.isArray(excludedIndexes) ? excludedIndexes.map(Number) : [];
    const used = {};
    const mappingOptions = columnMap && typeof columnMap === 'object' ? {
      columnMap: columnMap
    } : undefined;
    const columnName = function (index) {
      let number = Number(index) + 1;
      let letters = '';
      while (number > 0) {
        number -= 1;
        letters = String.fromCharCode(65 + number % 26) + letters;
        number = Math.floor(number / 26);
      }
      return 'Column ' + letters;
    };
    return sideElements(design, 'front').concat(sideElements(design, 'back')).reduce(function (fields, model) {
      if (!model || DESIGN_ONLY_TYPES.indexOf(model.type) !== -1) return fields;
      const index = mappedColumnIndex(model, mappingOptions);
      if (!Number.isInteger(index) || index < 0 || excluded.indexOf(index) !== -1 || used[index]) return fields;
      used[index] = true;
      fields.push({
        elementId: model.id,
        type: model.type,
        columnIndex: index,
        label: DATA_LABELS[model.type] || String(headers[index] || columnName(index)),
        header: String(headers[index] || columnName(index)),
        value: String(row[index] == null ? '' : row[index])
      });
      return fields;
    }, []);
  }
  function stableHash(value) {
    let hash = 2166136261;
    String(value || '').split('').forEach(function (character) {
      hash ^= character.charCodeAt(0);
      hash = Math.imul(hash, 16777619);
    });
    return (hash >>> 0).toString(36);
  }
  function getDataElements(design) {
    if (!design) return [];
    const output = [];
    ['front', 'back'].forEach(function (side) {
      sideElements(design, side).forEach(function (model, index) {
        if (!model || DESIGN_ONLY_TYPES.indexOf(model.type) !== -1) return;
        if (!model.id) model.id = 'element_' + side + '_' + index + '_' + stableHash(String(model.type || 'data') + '|' + String(model.x || 0) + '|' + String(model.y || 0));
        const legacy = model.columnIndex !== undefined && model.columnIndex !== null && model.columnIndex !== '' ? Number(model.columnIndex) : -1;
        output.push({
          id: String(model.id),
          type: String(model.type || 'text'),
          label: DATA_LABELS[model.type] || String(model.type || 'Data'),
          side: side,
          index: index,
          model: model,
          legacyColumnIndex: Number.isInteger(legacy) && legacy >= 0 ? legacy : -1
        });
      });
    });
    return output;
  }
  function mappingStorageKey(design, studioType) {
    const elements = getDataElements(design).map(function (item) {
      return item.id + ':' + item.type;
    }).join('|');
    const identity = design && design.designId ? String(design.designId) : stableHash([design && design.cardType, elements].join('|'));
    return 'id_card_column_mapping_v1_' + String(studioType || 'card').toLowerCase() + '_' + identity;
  }
  function loadColumnMapping(design, studioType) {
    try {
      const parsed = JSON.parse(STUDIO_STORAGE.getItem(mappingStorageKey(design, studioType)) || '{}');
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch (error) {
      return {};
    }
  }
  function saveColumnMapping(design, studioType, columnMap) {
    const clean = {};
    getDataElements(design).forEach(function (item) {
      const value = columnMap && columnMap[item.id];
      const index = value !== undefined && value !== null && value !== '' ? Number(value) : -1;
      if (Number.isInteger(index) && index >= 0) clean[item.id] = index;
    });
    STUDIO_STORAGE.setItem(mappingStorageKey(design, studioType), JSON.stringify(clean));
    return clean;
  }
  function applyColumnMapping(design, columnMap) {
    const map = columnMap && typeof columnMap === 'object' ? columnMap : {};
    getDataElements(design).forEach(function (item) {
      const value = map[item.id];
      const index = value !== undefined && value !== null && value !== '' ? Number(value) : -1;
      item.model.runtimeColumnIndex = Number.isInteger(index) && index >= 0 ? index : '';
    });
    return design;
  }
  function columnMappingStatus(design, columnMap) {
    const elements = getDataElements(design);
    const map = columnMap && typeof columnMap === 'object' ? columnMap : {};
    const mapped = elements.filter(function (item) {
      const index = Number(map[item.id]);
      return map[item.id] !== '' && map[item.id] !== null && map[item.id] !== undefined && Number.isInteger(index) && index >= 0;
    }).length;
    return {
      total: elements.length,
      mapped: mapped,
      missing: Math.max(0, elements.length - mapped),
      complete: elements.length === 0 || mapped === elements.length
    };
  }
  function openColumnMapper(settings) {
    return StudioReliability.openDesignMapping(settings || {});
  }
  function escapePrintHtml(value) {
    return String(value || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }
  function createPrintWindow(message) {
    const previewWindow = window.open('', 'idCardPrintPreview', 'width=1080,height=900,resizable=yes,scrollbars=yes');
    if (!previewWindow) {
      alert('Please allow pop-ups so the ID card print preview can open.');
      return null;
    }
    previewWindow.document.open();
    previewWindow.document.write('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Preparing ID Cards</title><style>*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;font-family:Arial,sans-serif;color:#172033;background:#eef2f7}.loading{width:min(520px,calc(100% - 32px));padding:30px;text-align:center;background:#fff;border:1px solid #d0d5dd;border-radius:16px;box-shadow:0 18px 45px rgba(23,32,51,.15)}.spinner{width:38px;height:38px;margin:0 auto 16px;border:4px solid #dbe4ef;border-top-color:#185adb;border-radius:50%;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}h1{margin:0 0 8px;font-size:21px}p{margin:0;color:#667085}</style></head><body><div class="loading"><div class="spinner"></div><h1>Preparing ID cards</h1><p id="printPreparationStatus">' + escapePrintHtml(message || 'Loading card photos and print data…') + '</p></div></body></html>');
    previewWindow.document.close();
    return previewWindow;
  }
  function openLargePrintPreview(container, options) {
    options = options || {};
    const cards = container ? Array.from(container.querySelectorAll('.album-design-card')) : [];
    if (!cards.length) {
      if (options.printWindow && !options.printWindow.closed) options.printWindow.close();
      alert('Please select and display an ID card before printing.');
      return null;
    }
    const landscape = cards[0].classList.contains('album-landscape');
    const pageSize = landscape ? '85.60mm 53.98mm' : '53.98mm 85.60mm';
    const pageWidth = landscape ? '85.60mm' : '53.98mm';
    const pageHeight = landscape ? '53.98mm' : '85.60mm';
    const dimensionLabel = landscape ? '85.60 × 53.98 mm' : '53.98 × 85.60 mm';
    const firstContext = renderContexts.get(cards[0].parentElement);
    const selectedCardType = firstContext && firstContext.design ? String(firstContext.design.cardType || '') : '';
    const formatLabels = {
      'portrait-hole': 'Portrait (Lanyard Hole)',
      'landscape-hole': 'Landscape (Lanyard Hole)',
      'portrait-plain': 'Portrait (No Hole)',
      'landscape-plain': 'Landscape (No Hole)'
    };
    const formatLabel = formatLabels[selectedCardType] || (landscape ? 'Landscape' : 'Portrait');
    const pixelWidth = landscape ? 324 : 204;
    const pixelHeight = landscape ? 204 : 324;
    const screenScale = 2;
    const previewTitle = 'Print Preview';
    const previewWindow = options.printWindow || createPrintWindow('Preparing print preview…');
    if (!previewWindow || previewWindow.closed) return null;
    function renderedCard(card, side) {
      const context = renderContexts.get(card.parentElement);
      if (!context) return side === 'front' ? card.outerHTML : '';
      const holder = document.createElement('div');
      const settings = Object.assign({}, context.options, {
        side: side
      });
      holder.style.cssText = 'position:fixed;left:-10000px;top:0;visibility:hidden;pointer-events:none';
      document.body.appendChild(holder);
      try {
        render(holder, context.design, context.record, settings);
        const output = holder.querySelector('.album-design-card');
        return output ? output.outerHTML : '';
      } finally {
        holder.remove();
      }
    }
    const cardHtml = cards.map(function (card, index) {
      return '<div class="preview-card-wrap" data-record-index="' + index + '" data-print-side="front">' + renderedCard(card, 'front') + '</div><div class="preview-card-wrap" data-record-index="' + index + '" data-print-side="back">' + renderedCard(card, 'back') + '</div>';
    }).join('');
    previewWindow.document.open();
    previewWindow.document.write(\`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>\${escapePrintHtml(previewTitle)}</title>
<style>
@page {
  size:\${pageSize};
  margin:0
}
* {
  box-sizing:border-box
}
html,body {
  margin:0
}
[hidden] {
  display:none!important
}
.preview-toolbar {
  position:sticky;
  top:0;
  z-index:10000;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:18px;
  padding:13px 20px;
  color:#fff;
  background:#172033;
  box-shadow:0 2px 10px rgba(0,0,0,.25);
  font-family:Arial,sans-serif
}
.preview-title {
  display:flex;
  flex-direction:column;
  gap:3px
}
.preview-title strong {
  font-size:16px
}
.preview-title span {
  color:#dce6f3;
  font-size:11px
}
.preview-actions {
  display:flex;
  align-items:center;
  flex-wrap:wrap;
  justify-content:flex-end;
  gap:9px
}
.side-picker {
  display:flex;
  align-items:center;
  gap:8px;
  font-size:13px;
  font-weight:700
}
.side-picker select {
  padding:9px 32px 9px 10px;
  border:1px solid #98a2b3;
  border-radius:7px;
  background:#fff;
  color:#172033;
  font-weight:700
}
.preview-actions button {
  padding:10px 18px;
  color:#fff;
  border:0;
  border-radius:7px;
  font-weight:700;
  cursor:pointer
}
.print-button {
  background:#185adb
}
.close-button {
  background:#667085
}
.print-help {
  padding:10px 18px;
  color:#344054;
  background:#fff6d8;
  border-bottom:1px solid #e6d9a4;
  font:600 12px/1.45 Arial,sans-serif;
  text-align:center
}
.preview-stage {
  min-height:calc(100vh - 110px);
  padding:36px;
  display:flex;
  flex-direction:column;
  align-items:center;
  gap:34px;
  background:#dfe5ec
}
.preview-card-wrap {
  width:\${pixelWidth * screenScale}px;
  height:\${pixelHeight * screenScale}px;
  flex:0 0 auto
}
.album-design-card {
  position:relative!important;
  width:\${pageWidth}!important;
  height:\${pageHeight}!important;
  margin:0!important;
  padding:0!important;
  overflow:hidden!important;
  background:#fff;
  border:0!important;
  box-shadow:0 12px 30px rgba(0,0,0,.28);
  transform:scale(\${screenScale});
  transform-origin:top left
}
.album-design-card * {
  box-sizing:border-box
}
.album-lanyard {
  width:56px;
  height:12px;
  position:absolute;
  z-index:999;
  top:7px;
  left:50%;
  transform:translateX(-50%);
  border-radius:8px
}
.album-element {
  position:absolute;
  min-width:1px;
  min-height:1px;
  display:flex;
  align-items:center;
  justify-content:center;
  overflow:visible;
  transform-origin:center
}
.album-element-text {
  width:100%;
  min-width:0;
  max-width:100%;
  max-height:100%;
  display:block;
  padding:1px 2px;
  line-height:1.08;
  white-space:normal;
  overflow-wrap:anywhere;
  word-break:normal;
  overflow:hidden
}
.album-element-text.justify,.album-element-text.auto-justified {
  text-align:justify;
  text-align-last:auto;
  text-justify:inter-word
}
.album-element img {
  width:100%;
  height:100%;
  display:block;
  object-fit:contain
}
.album-element.album-photo {
  overflow:hidden;
  border-radius:7px
}
.album-element.album-photo img {
  object-fit:cover
}
.album-photo-placeholder {
  width:100%;
  height:100%;
  display:grid;
  place-items:center
}
.album-barcode {
  width:100%;
  height:100%;
  display:block
}
.album-qr {
  width:100%;
  height:100%;
  display:grid;
  place-items:center;
  background:#fff
}
.album-qr svg {
  width:100%;
  height:100%;
  display:block
}
.album-grade {
  width:100%;
  height:100%;
  display:grid;
  grid-template-columns:minmax(0,1fr) minmax(0,1fr);
  gap:4px
}
.album-grade span {
  min-width:0;
  height:100%;
  display:flex;
  overflow:hidden
}
.album-grade.grade-pair-aligned {
  grid-auto-rows:max-content;
  align-items:baseline
}
.album-transport {
  width:100%;
  height:100%;
  display:flex;
  align-items:center;
  justify-content:center
}
.album-transport svg {
  width:90%;
  height:90%
}
@media(max-width:760px) {
  .preview-toolbar {
    align-items:flex-start;
    flex-direction:column
  }
  .preview-actions {
    justify-content:flex-start
  }
  .preview-stage {
    padding:24px 8px;
    overflow:auto
  }
}
@media print {
  html,body {
    width:\${pageWidth}!important;
    margin:0!important;
    padding:0!important;
    overflow:visible!important;
    background:#fff!important
  }
  body {
    -webkit-print-color-adjust:exact!important;
    print-color-adjust:exact!important
  }
  .preview-toolbar,.print-help {
    display:none!important
  }
  .preview-stage {
    min-height:0!important;
    padding:0!important;
    display:block!important;
    background:#fff!important
  }
  .preview-card-wrap {
    width:\${pageWidth}!important;
    height:\${pageHeight}!important;
    margin:0!important;
    overflow:hidden!important;
    page-break-after:always;
    break-after:page
  }
  .preview-card-wrap:last-child {
    page-break-after:auto;
    break-after:auto
  }
  .album-design-card {
    width:\${pageWidth}!important;
    height:\${pageHeight}!important;
    transform:none!important;
    border-radius:0!important;
    box-shadow:none!important
  }
  .album-lanyard {
    border-color:transparent!important
  }
}
</style>
</head>
<body>
<div class="preview-toolbar">
<div class="preview-title">
<strong>\${escapePrintHtml(previewTitle)}</strong>
<span>\${cards.length} card\${cards.length === 1 ? '' : 's'} · \${escapePrintHtml(formatLabel)} · \${dimensionLabel}</span>
</div>
<div class="preview-actions">
<label class="side-picker">Print Side <select id="printSide">
<option value="front">Front Side</option>
<option value="back">Back Side</option>
<option value="both">Front + Back</option>
</select>
</label>
<button class="print-button" onclick="requestPrint()">Print / Save as PDF</button>
</div>
</div>
<div class="print-help">Page layout: <strong>\${escapePrintHtml(formatLabel)}</strong>, \${dimensionLabel}. The on-screen preview is enlarged. In the print dialog, choose matching paper dimensions, 100% scale, and no margins or headers/footers. Both sides creates front/back pages for each record; it does not configure duplex printing. Check one test card before printing a batch.</div>
<main class="preview-stage">\${cardHtml}</main>
<script>
\${fitTextToBox.toString()}
const sideSelect = document.getElementById('printSide');
function fitPrintText() {
  // Hidden back pages cannot be measured. Expose both sides for this synchronous pass.
  const pages = Array.from(document.querySelectorAll('[data-print-side]'));
  const hidden = pages.map(page => page.hidden);
  pages.forEach(page => { page.hidden = false; });
  document.querySelectorAll('[data-fit-max-font-size]').forEach(function(text) {
    const host = text.dataset.fitSelf === 'true' ? text : text.closest('.album-element');
    fitTextToBox(host, text, Number(text.dataset.fitMaxFontSize), false, text.dataset.fitAlign);
  });
  pages.forEach((page, index) => { page.hidden = hidden[index]; });
}

function showSelectedSide() {
  const choice = sideSelect.value;
  document.querySelectorAll('[data-print-side]').forEach(function (item) {
    item.hidden = choice !== 'both' && item.dataset.printSide !== choice;
  });
}
async function requestPrint() {
  showSelectedSide();
  await document.fonts.ready;
  const images = Array.from(document.images);
  await Promise.all(images.map(img => img.decode ? img.decode().catch(() => {}) : Promise.resolve()));
  fitPrintText();
  try {
    if (typeof window.recordStudioPrintUsage === 'function') window.recordStudioPrintUsage();
  } catch (error) { /* Reporting must not block printing. */ }
  window.print();
  showSelectedSide();
}
sideSelect.addEventListener('change', function() { showSelectedSide(); fitPrintText(); });
showSelectedSide();
fitPrintText();
if (document.fonts) document.fonts.ready.then(fitPrintText);
window.addEventListener('beforeprint', fitPrintText);
<\\/script>
</body>
</html>\`);
    previewWindow.document.close();
    // Callback stays in the authenticated opener; no record content is sent.
    const usageStudio = String(window.STUDIO_TYPE || '').toLowerCase();
    previewWindow.recordStudioPrintUsage = function () {
      if (!['student', 'staff', 'custom'].includes(usageStudio)) return;
      try {
        google.script.run.withSuccessHandler(function () {}).withFailureHandler(function () {}).recordStudioPrintRequest(usageStudio);
      } catch (error) { /* Preview remains usable if the opener disconnects. */ }
    };
    previewWindow.focus();
    return previewWindow;
  }

  /** Search linked name values; Custom also searches other mapped design fields. */
  function matchingRecords(design, records, query, includeData) {
    const normalize = value => String(value == null ? '' : value).trim().toLowerCase().replace(/\\s+/g, ' ');
    const tokens = normalize(query).split(' ').filter(Boolean);
    if (!tokens.length) return [];
    return records.filter(record => {
      const values = ['fullName', 'firstName', 'lastName'].map(type => linkedValueForType(design, record, type) || record[type] || '');
      if (includeData || !values.some(Boolean)) getDataElements(design).forEach(item => values.push(boundValue(item.model, record, {})));
      const text = normalize(values.join(' '));
      return tokens.every(token => text.includes(token));
    });
  }
  function recordLabel(design, record) {
    const full = linkedValueForType(design, record, 'fullName') || record.fullName;
    const parts = ['firstName', 'lastName'].map(type => linkedValueForType(design, record, type) || record[type] || '').filter(Boolean);
    if (full || parts.length) return full || parts.join(' ');
    const values = getDataElements(design).map(item => boundValue(item.model, record, {})).filter(value => value !== null && String(value).trim());
    return values.slice(0, 2).join(' — ') || 'Record ' + (record._sheetRow || '');
  }
  function collectFormValues(host) {
    const columnValues = {};
    host.querySelectorAll('[data-column-index]').forEach(input => {
      columnValues[input.dataset.columnIndex] = input.value.trim();
    });
    return {
      columnValues: columnValues
    };
  }
  return {
    matchingRecords: matchingRecords,
    recordLabel: recordLabel,
    collectFormValues: collectFormValues,
    render: render,
    printCards: openLargePrintPreview,
    createPrintWindow: createPrintWindow,
    getPhotoKey: getPhotoKey,
    getBoundValue: boundValue,
    getLinkedValue: linkedValueForType,
    getDataElements: getDataElements,
    mappingStorageKey: mappingStorageKey,
    loadColumnMapping: loadColumnMapping,
    saveColumnMapping: saveColumnMapping,
    applyColumnMapping: applyColumnMapping,
    columnMappingStatus: columnMappingStatus,
    openColumnMapper: openColumnMapper,
    linkedFormFields: linkedFormFields,
    normalizeTypography: applyTypographyDefaults
  };
}();
</script>
`;

    case 'Landing':
      return `<!DOCTYPE html>
<html>
<head>
<script>
window.STUDIO_URL = <?!= JSON.stringify(webAppUrl) ?>;
window.STUDIO_TYPE = <?!= JSON.stringify(studioType) ?>;
window.STUDIO_SCOPE = <?!= JSON.stringify(clientScope) ?>;
window.STUDIO_STORAGE = {
  getItem: function (k) {
    return localStorage.getItem(STUDIO_SCOPE + k);
  },
  setItem: function (k, v) {
    localStorage.setItem(STUDIO_SCOPE + k, v);
  },
  removeItem: function (k) {
    localStorage.removeItem(STUDIO_SCOPE + k);
  }
};
</script>
<base target="_top">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {
  --ink: #172033;
  --muted: #667085;
  --line: #dce3ec;
  --student: #185adb;
  --staff: #7141c6;
  --custom: #0f8b8d;
  --design: #e66a13;
}
* {
  box-sizing: border-box;
}
body {
  min-height: 100vh;
  margin: 0;
  padding: 28px;
  font-family: "Segoe UI", Arial, sans-serif;
  color: var(--ink);
  background: radial-gradient(circle at 15% 15%, rgba(24,90,219,.12), transparent 28%), radial-gradient(circle at 85% 85%, rgba(113,65,198,.12), transparent 28%), #f4f7fb;
}
.portal {
  width: 100%;
  max-width: 1200px;
  margin: 24px auto;
}
.portal-header {
  margin-bottom: 28px;
  text-align: center;
}
.portal-mark {
  width: 82px;
  height: 82px;
  margin: 0 auto 15px;
  padding: 8px;
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 5px;
  color: #fff;
  background: linear-gradient(135deg, var(--student), var(--staff));
  border-radius: 22px;
  box-shadow: 0 12px 28px rgba(24,90,219,.22);
  font-weight: 800;
  transition: transform .18s ease;
}
.portal-mini {
  min-width: 0;
  min-height: 0;
  display: grid;
  place-items: center;
  overflow: hidden;
  border: 1px solid rgba(255,255,255,.45);
  border-radius: 9px;
  box-shadow: 0 3px 7px rgba(23,32,51,.2);
}
.portal-mini.student {
  background: var(--student);
}
.portal-mini.staff {
  background: var(--staff);
}
.portal-mini.custom {
  background: var(--custom);
}
.portal-mini.design {
  background: var(--design);
}
.portal-mini svg {
  width: 28px;
  height: 28px;
  display: block;
  filter: drop-shadow(0 2px 2px rgba(23,32,51,.18));
}
.portal-header:hover .portal-mark {
  transform: translateY(-2px) scale(1.06);
}
h1 {
  margin: 0;
  font-size: clamp(25px, 4vw, 34px);
}
.portal-header p {
  margin: 8px 0 0;
  color: var(--muted);
  font-size: 15px;
}
.choice-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
}
.choice-card {
  min-height: 225px;
  padding: 22px;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  color: inherit;
  text-decoration: none;
  background: rgba(255,255,255,.96);
  border: 1px solid var(--line);
  border-radius: 18px;
  box-shadow: 0 12px 35px rgba(33,48,73,.09);
  transition: transform .18s ease, box-shadow .18s ease, border-color .18s ease;
}
.choice-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 18px 42px rgba(33,48,73,.14);
}
.student-card:hover {
  border-color: #9db9ee;
}
.staff-card:hover {
  border-color: #c4afe7;
}
.custom-card:hover {
  border-color: #8fd8d2;
}
.design-card:hover {
  border-color: #f2bd8e;
}
.choice-icon {
  width: 48px;
  height: 48px;
  display: grid;
  place-items: center;
  color: #fff;
  border-radius: 13px;
  font-weight: 800;
  box-shadow: 0 8px 18px rgba(23,32,51,.16);
  transition: transform .18s ease, box-shadow .18s ease;
}
.choice-card:hover .choice-icon {
  transform: translateY(-2px) scale(1.08) rotate(-3deg);
  box-shadow: 0 11px 24px rgba(23,32,51,.22);
}
.student-card .choice-icon {
  background: var(--student);
}
.staff-card .choice-icon {
  background: var(--staff);
}
.custom-card .choice-icon {
  background: var(--custom);
}
.design-card .choice-icon {
  background: var(--design);
}
.choice-icon svg {
  width: 37px;
  height: 37px;
  display: block;
  filter: drop-shadow(0 3px 4px rgba(23,32,51,.22));
}
.choice-card h2 {
  margin: 18px 0 7px;
  font-size: 21px;
}
.choice-card p {
  margin: 0;
  color: var(--muted);
  line-height: 1.55;
  font-size: 14px;
}
.open-label {
  margin-top: auto;
  padding-top: 22px;
  color: var(--student);
  font-size: 13px;
  font-weight: 800;
}
.staff-card .open-label {
  color: var(--staff);
}
.custom-card .open-label {
  color: var(--custom);
}
.design-card .open-label {
  color: var(--design);
}
@media (max-width: 900px) {
  .choice-grid {
    grid-template-columns: 1fr 1fr;
  }
}
@media (max-width: 650px) {
  body {
    padding: 18px;
  }
  .choice-grid {
    grid-template-columns: 1fr;
  }
  .choice-card {
    min-height: 195px;
  }
}
</style>
<style>
.control-center-link {display:inline-flex;align-items:center;justify-content:center;gap:6px;margin-top:16px;padding:9px 14px;background:#243247;color:white;text-decoration:none;border-radius:7px;font-size:13px;font-weight:600;}
.control-center-link:hover {background:#edf3ff;border-color:#9db9ee;}
.control-center-link {gap:12px;padding:12px 16px;background:#f9fbfd;color:#172033;border:1px solid #dce3ec;border-radius:12px;text-align:left;box-shadow:0 5px 18px #24324709;}
.control-center-link strong {display:block;font-size:15px;}
.control-center-link small {display:block;margin-top:3px;font-size:12px;font-weight:400;color:#667085;}
.admin-icon {display:grid;place-items:center;width:42px;height:42px;background:#185adb;border-radius:10px;}
.admin-icon svg {width:32px;height:32px;}
</style>
</head>
<body>
<main class="portal">
<header class="portal-header">
<div class="portal-mark" role="img" aria-label="Student, Staff, Custom, and Design ID Card Studios">
<span class="portal-mini student">
<svg viewBox="0 0 48 48" aria-hidden="true">
<path d="M12 41c1-8 5.5-12 12-12s11 4 12 12" fill="#38d0b4"/>
<circle cx="24" cy="23" r="7" fill="#ffbf91"/>
<path d="M7 15L24 7l17 8-17 8-17-8z" fill="#ffd34e"/>
<path d="M14 19v5c5.5 4.8 14.5 4.8 20 0v-5" fill="#6f56d9"/>
<path d="M40 16v9" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/>
<circle cx="40" cy="27" r="2" fill="#ff7a59"/>
</svg>
</span>
<span class="portal-mini staff">
<svg viewBox="0 0 48 48" aria-hidden="true">
<path d="M10 42c.8-9 5.8-14 14-14s13.2 5 14 14" fill="#233c78"/>
<path d="M19 29l5 6 5-6" fill="#fff"/>
<path d="M23 34h2l2 8h-6l2-8z" fill="#ff5c70"/>
<circle cx="24" cy="19" r="8" fill="#f2b88f"/>
<path d="M16 18c.5-8 15-10 17-2-4-1-8-2-12-4-1 3-3 5-5 6z" fill="#51362b"/>
<rect x="31" y="30" width="10" height="8" rx="2" fill="#ffd34e"/>
</svg>
</span>
<span class="portal-mini custom">
<svg viewBox="0 0 48 48" aria-hidden="true">
<rect x="5" y="9" width="38" height="30" rx="6" fill="#fff"/>
<circle cx="16" cy="23" r="6" fill="#9f7aea"/>
<path d="M9 35c1-5.5 3.5-8 7-8s6 2.5 7 8" fill="#ff8a65"/>
<rect x="26" y="17" width="11" height="3" rx="1.5" fill="#2563eb"/>
<circle cx="37" cy="34" r="7" fill="#ffd34e"/>
<path d="M37 30v8M33 34h8" stroke="#7b4f00" stroke-width="2.5" stroke-linecap="round"/>
</svg>
</span>
<span class="portal-mini design">
<svg viewBox="0 0 48 48" aria-hidden="true">
<path d="M24 7C13 7 6 14.5 6 24s7.7 17 17 17h3c2.2 0 3.2-2.7 1.6-4.2-1.3-1.2-.5-3.4 1.3-3.4h5.6c5 0 7.5-3.7 7.5-8.4C42 14.7 34.2 7 24 7z" fill="#fff4d6"/>
<circle cx="15" cy="20" r="3" fill="#ff5c70"/>
<circle cx="22" cy="14" r="3" fill="#ffd34e"/>
<circle cx="30" cy="16" r="3" fill="#38d0b4"/>
<circle cx="34" cy="24" r="3" fill="#5b8cff"/>
<path d="M17 38l15-18 5 4-15 18-6 1 1-5z" fill="#7141c6"/>
</svg>
</span>
</div>
<h1>ID Card Studio</h1>
<p>Choose a studio to manage records and print cards, or open Design Studio to create a layout.</p>
<? if (typeof isAdministrator !== 'undefined' && isAdministrator === true) { ?>
<a class="control-center-link" href="<?= webAppUrl ?>?studio=control-center" target="_top"><span class="admin-icon"><svg viewBox="0 0 48 48" aria-hidden="true"><path d="M24 4 41 11v12c0 10-7 17-17 22C14 40 7 33 7 23V11Z" fill="#a9c8ff"/><path d="m16 24 6 6 12-13" fill="none" stroke="#185adb" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg></span><span><strong>Control Center</strong><small>Manage user access · Administrator only</small></span><span aria-hidden="true">→</span></a>
<? } ?>
</header>
<section class="choice-grid" aria-label="Choose ID card type">
<a class="choice-card student-card" href="<?!= webAppUrl ?>?screen=student-studio&amp;studio=student&amp;routeVersion=3" target="_top">
<div class="choice-icon" role="img" aria-label="Student">
<svg viewBox="0 0 48 48" aria-hidden="true">
<path d="M12 41c1-8 5.5-12 12-12s11 4 12 12" fill="#38d0b4"/>
<circle cx="24" cy="23" r="7" fill="#ffbf91"/>
<path d="M7 15L24 7l17 8-17 8-17-8z" fill="#ffd34e"/>
<path d="M14 19v5c5.5 4.8 14.5 4.8 20 0v-5" fill="#6f56d9"/>
<path d="M40 16v9" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/>
<circle cx="40" cy="27" r="2" fill="#ff7a59"/>
</svg>
</div>
<h2>Student ID Card</h2>
<p>Connect student data, select a design, and map its columns. Find students by name, ID number, or grade; take photos and preview or print cards.</p>
<span class="open-label">Open Student Studio →</span>
</a>
<a class="choice-card staff-card" href="<?!= webAppUrl ?>?screen=staff-studio&amp;studio=staff&amp;routeVersion=3" target="_top">
<div class="choice-icon" role="img" aria-label="Staff">
<svg viewBox="0 0 48 48" aria-hidden="true">
<path d="M10 42c.8-9 5.8-14 14-14s13.2 5 14 14" fill="#233c78"/>
<path d="M19 29l5 6 5-6" fill="#fff"/>
<path d="M23 34h2l2 8h-6l2-8z" fill="#ff5c70"/>
<circle cx="24" cy="19" r="8" fill="#f2b88f"/>
<path d="M16 18c.5-8 15-10 17-2-4-1-8-2-12-4-1 3-3 5-5 6z" fill="#51362b"/>
<rect x="31" y="30" width="10" height="8" rx="2" fill="#ffd34e"/>
<circle cx="34" cy="33" r="1.5" fill="#7141c6"/>
<path d="M37 33h2M34 36h5" stroke="#7141c6" stroke-width="1.3" stroke-linecap="round"/>
</svg>
</div>
<h2>Staff ID Card</h2>
<p>Connect staff data, select a design, and map its columns. Search by name, manage records and photos, and preview or print one or all staff cards.</p>
<span class="open-label">Open Staff Studio →</span>
</a>
<a class="choice-card custom-card" href="<?!= webAppUrl ?>?screen=custom-studio&amp;studio=custom&amp;routeVersion=3" target="_top">
<div class="choice-icon" role="img" aria-label="Custom ID card">
<svg viewBox="0 0 48 48" aria-hidden="true">
<rect x="5" y="9" width="38" height="30" rx="6" fill="#fff"/>
<circle cx="16" cy="23" r="6" fill="#9f7aea"/>
<path d="M9 35c1-5.5 3.5-8 7-8s6 2.5 7 8" fill="#ff8a65"/>
<rect x="26" y="17" width="11" height="3" rx="1.5" fill="#2563eb"/>
<rect x="26" y="23" width="9" height="3" rx="1.5" fill="#22b8a7"/>
<circle cx="37" cy="34" r="7" fill="#ffd34e"/>
<path d="M37 30v8M33 34h8" stroke="#7b4f00" stroke-width="2.5" stroke-linecap="round"/>
</svg>
</div>
<h2>Custom ID Card</h2>
<p>Connect a separate spreadsheet and photo folder. Map your chosen design, search and manage records, and preview or print custom cards.</p>
<span class="open-label">Open Custom Studio →</span>
</a>
<a id="openDesignStudio" class="choice-card design-card" href="<?!= webAppUrl ?>?screen=card-designer-v3" target="_top">
<div class="choice-icon" role="img" aria-label="Design">
<svg viewBox="0 0 48 48" aria-hidden="true">
<path d="M24 7C13 7 6 14.5 6 24s7.7 17 17 17h3c2.2 0 3.2-2.7 1.6-4.2-1.3-1.2-.5-3.4 1.3-3.4h5.6c5 0 7.5-3.7 7.5-8.4C42 14.7 34.2 7 24 7z" fill="#fff4d6"/>
<circle cx="15" cy="20" r="3" fill="#ff5c70"/>
<circle cx="22" cy="14" r="3" fill="#ffd34e"/>
<circle cx="30" cy="16" r="3" fill="#38d0b4"/>
<circle cx="34" cy="24" r="3" fill="#5b8cff"/>
<path d="M17 38l15-18 5 4-15 18-6 1 1-5z" fill="#7141c6"/>
<path d="M32 20l5 4" stroke="#fff" stroke-width="2"/>
</svg>
</div>
<h2>Design Studio</h2>
<p>Create front and back layouts, arrange visual and data elements, and save reusable design files. Link spreadsheet columns later in a Card Studio.</p>
<span class="open-label">Open Design Studio →</span>
</a>
</section>
<? if (typeof isAdministrator !== 'undefined' && isAdministrator === true) { ?>
<p style="margin:20px 4px 0;color:#667085;font-size:12px;line-height:1.5;text-align:center">Usage reporting: administrators can see your account email, visit times, studio openings, photo-save counts, and print requests. Your record contents, photos, and source links are not included.</p>
<? } ?>
</main>
<?!= include('ReliabilityClient'); ?>
</body>
</html>
`;

    case 'ReliabilityClient':
      return `<style>
.studio-reliability-bar {
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  padding:10px 16px;
  background:#f0f5ff;
  border:1px solid #c7d7ee;
  border-radius:10px;
  margin:12px 0;
  color:#17233a;
  font:13px/1.5 'Segoe UI',sans-serif
}
.studio-reliability-bar button {
  border:1px solid #a9b8cf;
  border-radius:7px;
  background:white;
  color:#17233a;
  padding:7px 12px;
  cursor:pointer;
  font-weight:600
}
.reliability-dialog {
  max-width:620px;
  width:90%;
  padding:24px;
  border:1px solid #c7d7ee;
  border-radius:14px;
  color:#17233a;
  font:14px/1.5 'Segoe UI',sans-serif
}
.reliability-dialog::backdrop {
  background:#17233a88
}
.reliability-dialog label {
  display:block;
  margin:12px 0
}
.reliability-dialog select {
  width:100%;
  padding:9px
}
.reliability-dialog button {
  margin:8px 6px 0 0;
  padding:9px 14px
}
.reliability-dialog .error {
  color:#b42318
}
.header-actions {
  display:flex;
  flex-wrap:wrap;
  align-items:center;
  justify-content:flex-end;
  gap:9px;
}
.studio-nav-button {
  border:0;
  border-radius:10px;
  padding:11px 14px;
  font:700 13px 'Segoe UI',sans-serif;
  color:#fff;
  cursor:pointer;
}
.studio-nav-button.clear-local {
  background:#b42318;
}
.studio-nav-button.refresh-records {
  background:#185adb;
}
.studio-nav-button:disabled {
  opacity:.55;
  cursor:wait;
}
.studio-icon-button::before {
  content:attr(data-studio-icon);
  display:inline-block;
  margin-right:.45em;
  font-size:1.05em;
  line-height:1;
}
.studio-card-count {
  margin:0;
  padding:12px 20px 0;
  color:#475467;
  font-size:13px;
  font-weight:700;
}
.unified-preview-header {
  display:grid!important;
  grid-template-columns:minmax(0,1fr) auto;
  align-items:start!important;
  gap:16px!important;
}
.unified-preview-header > div:empty {
  display:none!important;
}
.unified-preview-header > div:first-child {
  grid-column:1;
  grid-row:1;
}
.unified-preview-header p {
  max-width:62ch;
}
.unified-preview-header button[id^="previewAll"] {
  display:inline-flex;
  align-items:center;
  width:auto;
  margin-top:12px;
}
.studio-print-actions {
  grid-column:2;
  grid-row:1;
  display:flex;
  justify-content:flex-end;
  align-self:start;
}
.legacy-design-choice {
  display:none!important;
}
.design-mapping-dialog {
  width:min(960px,94vw);
  max-width:960px;
  max-height:90vh;
  padding:24px;
  box-sizing:border-box;
  border:1px solid #d0d5dd;
  border-radius:16px;
  overflow:auto;
}
.design-mapping-dialog::backdrop {
  background:#10182888;
}
.mapping-form {
  display:flex;
  flex-direction:column;
  gap:14px;
}
.mapping-form h2 {
  margin:0;
  color:#172033;
}
.mapping-form p {
  margin:6px 0;
  line-height:1.5;
}
.mapping-options {
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:14px;
  padding:16px;
  background:#f5f7fb;
  border-radius:10px;
}
.mapping-options label {
  display:flex;
  flex-direction:column;
  gap:7px;
  font-weight:700;
}
.mapping-options input[type="file"] {
  display:block!important;
  width:100%;
  font-size:13px;
}
.mapping-options .mapping-header-check {
  flex-direction:row;
  align-items:center;
}
.mapping-header-check input {
  width:auto!important;
}
.mapping-design-name {
  align-self:center;
  font-size:13px;
  overflow-wrap:anywhere;
}
.mapping-form select {
  width:100%;
  padding:9px;
  border:1px solid #cbd5e1;
  border-radius:7px;
  background:#fff;
  box-sizing:border-box;
}
.mapping-help {
  color:#667085;
  font-size:13px;
}
.mapping-table-scroll {
  overflow:auto;
  max-height:42vh;
}
.mapping-table-scroll table {
  border-collapse:collapse;
  width:100%;
  text-align:left;
}
.mapping-table-scroll th,.mapping-table-scroll td {
  border-bottom:1px solid #e4e7ec;
  padding:10px;
  overflow-wrap:anywhere;
}
.mapping-table-scroll th {
  background:#eff4ff;
  position:sticky;
  top:0;
}
.mapping-table-scroll td:nth-child(2) {
  min-width:200px;
}
.mapping-form footer {
  display:flex;
  justify-content:flex-end;
  gap:10px;
}
.mapping-form button {
  padding:10px 15px;
  border:0;
  border-radius:8px;
  cursor:pointer;
  font-weight:700;
}
#mappingSave {
  background:#15803d;
  color:#fff;
}
#mappingCancel {
  background:#e4e7ec;
  color:#344054;
}
#mappingSave:disabled {
  opacity:.5;
  cursor:wait;
}
#mappingStatus.error {
  color:#b42318;
}
@media(max-width:900px) {
  .unified-preview-header {
    grid-template-columns:1fr!important;
  }
  .studio-print-actions {
    grid-column:1;
    grid-row:2;
    justify-content:flex-end;
    max-width:none;
  }
  .mapping-options {
    grid-template-columns:1fr;
  }
}
@media print {
  .studio-card-count,.studio-print-actions,.header-actions {
    display:none!important;
  }
}
.studio-data-tools {
  margin:12px 0 16px;
}
.studio-data-actions {
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:8px;
}
.studio-data-tools .source-note {
  margin:6px 0 0;
  color:#667085;
  font-size:11px;
  font-weight:400;
  line-height:1.4;
}
.studio-data-tools .source-note span {
  display:block;
  margin-top:6px;
  font-size:inherit;
  line-height:inherit;
}
.studio-data-actions button {
  width:100%;
}
#studioPhotoError {
  padding:12px;
  color:#a12622;
  background:#fff3f1;
  border-radius:8px;
}
@media print {
  #studioPhotoError {
    display:none!important;
  }
}

/* Uniform action sizing. Colors and existing layout widths are preserved. */
.studio-sized-action {
  box-sizing:border-box!important;
  min-height:38px!important;
  height:38px!important;
  padding:8px 12px!important;
  font-size:12px!important;
  line-height:20px!important;
  font-weight:600!important;
  border-radius:8px!important;
  white-space:nowrap;
  vertical-align:middle;
}
a.studio-sized-action {display:inline-flex;align-items:center;justify-content:center;gap:5px;}
.studio-sized-tool {
  box-sizing:border-box!important;
  min-height:30px!important;
  height:30px!important;
  padding:4px 8px!important;
  font-size:12px!important;
  line-height:20px!important;
}
.studio-sized-search {width:30px!important;min-width:30px!important;height:30px!important;padding:4px!important;}
.studio-print-actions {
  flex-direction:column;
  flex-wrap:nowrap;
  align-items:stretch;
  width:220px;
  max-width:100%;
  gap:8px;
}
.studio-print-actions button {
  display:flex;
  align-items:center;
  justify-content:center;
  width:100%!important;
  min-height:38px!important;
  height:38px!important;
  margin:0!important;
  white-space:nowrap;
}
@media(max-width:400px) {
  .studio-sized-action {white-space:normal;height:auto!important;}
}
</style>
<script>
window.StudioReliability = function () {
  const sessions = new WeakMap();
  const photoStates = new Map();
  const photoCache = new Map();
  let manifestPromise = null;
  let manifestTime = 0;
  let running = 0;
  const queue = [];
  function call(name, ...args) {
    return new Promise((resolve, reject) => google.script.run.withSuccessHandler(resolve).withFailureHandler(reject)[name](...args));
  }
  function queuedCall(name, ...args) {
    return new Promise((resolve, reject) => {
      queue.push(() => call(name, ...args).then(resolve, reject));
      pump();
    });
  }
  function pump() {
    while (running < 4 && queue.length) {
      const task = queue.shift();
      running++;
      task().finally(() => {
        running--;
        pump();
      });
    }
  }
  function registerPopup(popup) {
    if (!popup) return;
    const token = crypto.randomUUID();
    sessions.set(popup, token);
    popup.__STUDIO_TOKEN = token;
  }
  window.addEventListener('message', function (event) {
    const value = event.data;
    if (!value || !['SAVE_STUDENT', 'DELETE_STUDENT', 'CAPTURED_PHOTO', 'STAFF_CAPTURED_PHOTO', 'CUSTOM_CAPTURED_PHOTO'].includes(value.type)) return;
    const token = event.source && sessions.get(event.source);
    if (!token || value.sessionToken !== token || event.origin !== (window.STUDIO_FRAME_ORIGIN || location.origin) && event.origin !== 'null') {
      event.stopImmediatePropagation();
      return;
    }
    if (value.type.includes('PHOTO') && (typeof value.dataUrl !== 'string' || value.dataUrl.length > 14000000 || !/^data:image\\/(jpeg|png);base64,[A-Za-z0-9+/=]+$/.test(value.dataUrl))) {
      event.stopImmediatePropagation();
      alert('Invalid photo message. Capture the photo again.');
    }
  }, true);
  function currentRecords() {
    if (STUDIO_TYPE === 'staff') return typeof staffRecords !== 'undefined' ? staffRecords : [];
    if (STUDIO_TYPE === 'custom') return typeof getCustomRecordsForReliability === 'function' ? getCustomRecordsForReliability() : [];
    return typeof recordsList !== 'undefined' ? recordsList : [];
  }
  function invalidate() {
    manifestPromise = null;
    manifestTime = 0;
    photoStates.clear();
    const notice = document.getElementById('studioPhotoError');
    if (notice) notice.remove();
    photoCache.clear();
  }
  function reopen() {
    if (window.StudioTabsBridge) {
      window.StudioTabsBridge.reload();
      return;
    }
    const url = STUDIO_URL + '?studio=' + encodeURIComponent(STUDIO_TYPE === 'landing' ? '' : STUDIO_TYPE);
    const dialog = document.createElement('dialog');
    dialog.className = 'reliability-dialog';
    const title = document.createElement('h2');
    title.textContent = 'Settings Saved';
    const text = document.createElement('p');
    text.textContent = 'Reopen this studio to use its current data sources and saved settings.';
    const link = document.createElement('a');
    link.href = url;
    link.target = '_top';
    link.textContent = 'Continue to Studio';
    link.style.cssText = 'display:inline-block;padding:10px 16px;background:#185adb;color:white;border-radius:7px';
    dialog.append(title, text, link);
    document.body.append(dialog);
    dialog.showModal();
    try {
      window.top.location.href = url;
    } catch (e) {/* Explicit link remains available when the iframe blocks automatic navigation. */}
  }
  async function photo(type, key) {
    if (!key) return '';
    photoStates.set(key, 'loading');
    try {
      if (!manifestPromise || Date.now() - manifestTime > 60000) {
        manifestTime = Date.now();
        const keys = currentRecords().map(r => r.recordKey);
        if (!keys.includes(key)) keys.push(key);
        manifestPromise = call('getStudioPhotoManifest', type, keys).catch(e => {
          manifestPromise = null;
          throw e;
        });
      }
      let all = await manifestPromise;
      let entry = all.find(e => String(e.key) === String(key));
      if (!entry) {
        entry = (await call('getStudioPhotoManifest', type, [key]))[0];
      }
      if (entry.status === 'failed') throw new Error(entry.error);
      if (entry.status === 'missing') {
        photoStates.set(key, 'missing');
        return '';
      }
      const cacheKey = entry.fileId + ':' + entry.updated;
      if (photoCache.has(cacheKey)) {
        photoStates.set(key, 'ready');
        return photoCache.get(cacheKey);
      }
      let data;
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          data = await queuedCall('getStudioPhotoFile', type, entry.fileId);
          break;
        } catch (e) {
          if (attempt) throw e;
          await new Promise(r => setTimeout(r, 400));
        }
      }
      photoCache.set(cacheKey, data);
      photoStates.set(key, 'ready');
      return data;
    } catch (e) {
      photoStates.set(key, 'failed');
      let notice = document.getElementById('studioPhotoError');
      if (!notice) {
        notice = document.createElement('p');
        notice.id = 'studioPhotoError';
        notice.setAttribute('role', 'alert');
        const mount = document.getElementById(STUDIO_TYPE === 'student' ? 'cardsWrapper' : 'cardMount');
        if (mount) mount.before(notice);
      }
      notice.textContent = 'Photo loading: ' + (e.message || String(e));
      throw e;
    }
  }
  /** One source/design/worksheet/header/column workflow for all card studios. */
  async function openDesignMapping(settings) {
    settings = settings || {};
    const previous = document.getElementById('designMappingDialog');
    if (previous) previous.remove();
    const dialog = document.createElement('dialog');
    dialog.id = 'designMappingDialog';
    dialog.className = 'reliability-dialog design-mapping-dialog';
    dialog.innerHTML = \`<form method="dialog" class="mapping-form">
<header>
<h2>Design Mapping</h2>
<p>Select a card design, worksheet, header setting, and data columns. Nothing changes until you save.</p>
</header>
<div class="mapping-options">
<label>Card design <input id="mappingDesignFile" type="file" accept=".json,application/json">
</label>
<p id="mappingDesignName" class="mapping-design-name">
</p>
<label>Worksheet <select id="mappingWorksheet">
</select>
</label>
<label class="mapping-header-check">
<input id="mappingHeader" type="checkbox"> First row contains headers</label>
</div>
<p class="mapping-help">Choose columns by their position and sample value. Logo, Image, Photo Frame, and School Year do not require a column.</p>
<div class="mapping-table-scroll">
<table>
<thead>
<tr>
<th>Design element</th>
<th>Spreadsheet column</th>
<th>Sample value</th>
</tr>
</thead>
<tbody id="mappingRows">
</tbody>
</table>
</div>
<p class="mapping-help">Saving reuses the record/photo columns. Duplicate app-created columns are consolidated; your data rows and linked photos are preserved.</p>
<p id="mappingStatus" role="status">
</p>
<footer>
<button type="button" id="mappingSave">Save Design Mapping</button>
<button type="button" id="mappingCancel">Cancel</button>
</footer>
</form>\`;
    document.body.appendChild(dialog);
    const worksheet = dialog.querySelector('#mappingWorksheet');
    const header = dialog.querySelector('#mappingHeader');
    const status = dialog.querySelector('#mappingStatus');
    const save = dialog.querySelector('#mappingSave');
    const fileInput = dialog.querySelector('#mappingDesignFile');
    let design = settings.design ? JSON.parse(JSON.stringify(settings.design)) : null;
    let info = null;
    let working = {};
    let sourceKey = '';
    let request = 0;
    let busy = false;
    let saving = false;
    dialog.querySelector('form').onsubmit = event => event.preventDefault();
    function showError(error) {
      status.textContent = error.message || String(error);
      status.className = 'error';
    }
    function validDesign(value) {
      if (!value || value.fileType !== 'ID_CARD_DESIGN' || !Array.isArray(value.frontElements) && !Array.isArray(value.elements)) throw new Error('Choose an ID Card Design .json file saved in Design Studio.');
      value.frontElements = value.frontElements || value.elements || [];
      value.backElements = value.backElements || [];
      value.elements = value.frontElements;
      value.dataSource = STUDIO_TYPE;
      return value;
    }
    function savedMap() {
      if (!design || !info) return {};
      try {
        return JSON.parse(localStorage.getItem(info.scope + CardDesignRuntime.mappingStorageKey(design, STUDIO_TYPE)) || '{}');
      } catch (error) {
        return {};
      }
    }
    function renderRows() {
      const body = dialog.querySelector('#mappingRows');
      body.replaceChildren();
      dialog.querySelector('#mappingDesignName').textContent = design ? 'Selected: ' + (design.selectedFileName || design.name || 'ID Card Design') : 'Choose a saved design from your device.';
      if (!info || !design) {
        save.disabled = true;
        return;
      }
      const elements = CardDesignRuntime.getDataElements(design);
      elements.forEach(element => {
        const row = document.createElement('tr');
        const name = document.createElement('td');
        name.textContent = element.label + ' — ' + (element.side === 'back' ? 'Back' : 'Front');
        const cell = document.createElement('td');
        const select = document.createElement('select');
        select.setAttribute('aria-label', element.label + ' spreadsheet column');
        select.add(new Option('Not linked', ''));
        info.columns.forEach(column => select.add(new Option(column.label, String(column.index))));
        if (working[element.id] !== undefined && info.columns.some(column => column.index === Number(working[element.id]))) select.value = String(working[element.id]);else delete working[element.id];
        const sample = document.createElement('td');
        const update = () => {
          if (select.value === '') delete working[element.id];else working[element.id] = Number(select.value);
          const column = info.columns.find(item => String(item.index) === select.value);
          sample.textContent = column ? column.sample || '(blank)' : '—';
        };
        select.onchange = update;
        update();
        cell.appendChild(select);
        row.append(name, cell, sample);
        body.appendChild(row);
      });
      if (!elements.length) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 3;
        cell.textContent = 'This design contains only design elements. No column links are required.';
        row.append(cell);
        body.append(row);
      }
      save.disabled = busy;
    }
    async function loadInfo(sheetId, hasHeader) {
      const token = ++request;
      busy = true;
      save.disabled = true;
      status.textContent = 'Reading worksheet…';
      status.className = '';
      try {
        const next = await call('getDesignMappingInfo', STUDIO_TYPE, settings.spreadsheetUrl || '', sheetId, hasHeader);
        if (token !== request || !dialog.isConnected) return;
        const nextKey = next.spreadsheetId + ':' + next.sheetId;
        info = next;
        worksheet.replaceChildren();
        info.worksheets.forEach(sheet => worksheet.add(new Option(sheet.name, String(sheet.id))));
        worksheet.value = String(info.sheetId);
        header.checked = info.header;
        if (sourceKey !== nextKey) working = savedMap();
        sourceKey = nextKey;
        busy = false;
        status.textContent = '';
        renderRows();
      } catch (error) {
        if (token === request) {
          busy = false;
          showError(error);
          save.disabled = true;
        }
      }
    }
    worksheet.onchange = () => loadInfo(worksheet.value, header.checked);
    header.onchange = () => loadInfo(worksheet.value, header.checked);
    fileInput.onchange = async () => {
      const file = fileInput.files[0];
      if (!file) return;
      try {
        const next = validDesign(JSON.parse(await file.text()));
        next.selectedFileName = file.name;
        next.name = String(next.name || '').trim() || file.name.replace(/\\.json$/i, '');
        design = next;
        working = savedMap();
        status.textContent = '';
        renderRows();
      } catch (error) {
        showError(error);
      }
    };
    function close() {
      if (saving) return;
      request++;
      dialog.close();
      dialog.remove();
    }
    dialog.querySelector('#mappingCancel').onclick = close;
    dialog.addEventListener('cancel', event => {
      event.preventDefault();
      close();
    });
    save.onclick = async () => {
      if (busy || !info || !design) return;
      busy = true;
      saving = true;
      save.disabled = true;
      worksheet.disabled = true;
      header.disabled = true;
      fileInput.disabled = true;
      status.textContent = 'Saving design mapping…';
      status.className = '';
      try {
        // Check browser storage before committing the spreadsheet connection.
        const preflight = STUDIO_SCOPE + 'mapping_preflight';
        localStorage.setItem(preflight, JSON.stringify(design));
        localStorage.removeItem(preflight);
        const fields = CardDesignRuntime.getDataElements(design).filter(element => working[element.id] !== undefined).map(element => ({
          id: element.id,
          type: element.type,
          columnIndex: working[element.id]
        }));
        const result = await call('saveDesignMapping', STUDIO_TYPE, {
          spreadsheetUrl: settings.spreadsheetUrl || '',
          sheetId: info.sheetId,
          header: header.checked,
          fields: fields,
          layoutToken: info.layoutToken
        });
        const map = {};
        result.fields.forEach(field => {
          map[field.id] = field.columnIndex;
        });
        CardDesignRuntime.applyColumnMapping(design, map);
        localStorage.setItem(result.scope + 'active_' + STUDIO_TYPE + '_card_design', JSON.stringify(design));
        localStorage.setItem(result.scope + CardDesignRuntime.mappingStorageKey(design, STUDIO_TYPE), JSON.stringify(map));
        busy = false;
        saving = false;
        close();
        reopen();
      } catch (error) {
        busy = false;
        saving = false;
        save.disabled = false;
        worksheet.disabled = false;
        header.disabled = false;
        fileInput.disabled = false;
        showError(error);
      }
    };
    dialog.showModal();
    renderRows();
    await loadInfo();
  }
  async function refreshRecordsAndPhotos(button) {
    if (button) button.disabled = true;
    const selectedId = STUDIO_TYPE === 'student' ? activeStudentId : STUDIO_TYPE === 'staff' ? activeStaffId : activeId;
    const query = window.activeNameSearch;
    try {
      invalidate();
      if (STUDIO_TYPE === 'student') Object.keys(studentPhotoCache).forEach(key => delete studentPhotoCache[key]);
      const method = STUDIO_TYPE === 'student' ? 'getStudentData' : STUDIO_TYPE === 'staff' ? 'getStaffData' : 'getCustomData';
      const data = await call(method);
      if (STUDIO_TYPE === 'student') populateRecordsDropdown(data, selectedId);else if (STUDIO_TYPE === 'staff') populateStaff(data, selectedId);else populate(data, selectedId);
      if (query) {
        const input = document.getElementById(STUDIO_TYPE === 'student' ? 'studentNameSearchInput' : STUDIO_TYPE === 'staff' ? 'staffSearchInput' : 'customRecordSearchInput');
        input.value = query;
        if (STUDIO_TYPE === 'student') searchStudentByFullName();else if (STUDIO_TYPE === 'staff') searchStaffByName();else searchCustomRecord();
      }
    } catch (error) {
      alert('Unable to refresh: ' + (error.message || String(error)));
    } finally {
      if (button) button.disabled = false;
    }
  }
  async function clearLocalData() {
    if (!confirm('Clear this studio’s local design, mappings, and cached photos, and regenerate its internal record codes? Spreadsheet data, linked photos, and design files saved on your device will remain.')) return;
    try {
      try {
        await call('resetStudioRecordCodes', STUDIO_TYPE);
      } catch (error) {
        alert('The spreadsheet could not be reset: ' + (error.message || error) + '\\nLocal data will still be cleared. Spreadsheet records and photos will remain unchanged.');
      }
      window.__CLEARING_LOCAL_DATA = true;
      Object.keys(localStorage).filter(key => key.startsWith(STUDIO_SCOPE)).forEach(key => localStorage.removeItem(key));
      if (STUDIO_TYPE === 'student' && typeof studentPhotoDatabasePromise !== 'undefined' && studentPhotoDatabasePromise) {
        const db = await studentPhotoDatabasePromise;
        if (db) db.close();
      }
      if (window.indexedDB && indexedDB.databases) {
        const databases = await indexedDB.databases();
        await Promise.all(databases.filter(db => db.name && db.name.startsWith(STUDIO_SCOPE)).map(db => new Promise(resolve => {
          const request = indexedDB.deleteDatabase(db.name);
          request.onsuccess = resolve;
          request.onerror = resolve;
          request.onblocked = resolve;
        })));
      }
      invalidate();
      reopen();
    } catch (error) {
      alert('Unable to clear this studio: ' + (error.message || String(error)));
    }
  }
  function decorateButtons(root) {
    const symbols = {
      print: '🖨',
      preview: '▣',
      refresh: '↻',
      clear: '⌫',
      map: '⇄',
      home: '⌂',
      photo: '📷',
      folder: '📁',
      sheet: '▦',
      add: '＋',
      edit: '✎',
      delete: '🗑',
      save: '✓',
      cancel: '×',
      search: '⌕',
      download: '⇩',
      connect: '↗',
      generic: '›'
    };
    root.querySelectorAll('button, a.id-studio-link, a.btn.home').forEach(button => {
      // Keep drag handles and tab-close targets independent of action sizing.
      if (button.closest('.rotate-handle, .resize-handle') || button.classList.contains('tab-close')) return;
      const original = button.textContent.trim();
      let shortLabel = original;
      if (/^Preview All (Student|Staff|Custom) ID Cards$/i.test(original)) shortLabel = 'Preview All Cards';
      else if (/^Print Displayed (Student|Staff|Custom) ID Cards$/i.test(original)) shortLabel = 'Print Displayed Cards';
      else if (/^Print All (Student|Staff|Custom) ID Cards$/i.test(original)) shortLabel = 'Print All Cards';
      else if (/^Open the Spreadsheet$/i.test(original)) shortLabel = 'Open Spreadsheet';
      else if (/^Open the Photo Folder$/i.test(original)) shortLabel = 'Open Photo Folder';
      if (shortLabel !== original) {
        if (!button.title) button.title = original;
        button.textContent = shortLabel;
      }
      const compact = STUDIO_TYPE === 'design' && button.closest('.sidebar, .canvas-toolbar, .design-tabs-wrap');
      if (compact) {
        button.classList.add('studio-sized-tool');
        return;
      }
      if (button.classList.contains('search-btn')) {
        button.classList.add('studio-sized-search');
        return;
      }
      button.classList.add('studio-sized-action');
      const text = button.textContent.trim().toLowerCase();
      const action = /print/.test(text) ? 'print' : /preview/.test(text) ? 'preview' : /refresh|retry/.test(text) ? 'refresh' : /clear data|clear local/.test(text) ? 'clear' : /mapping|worksheet/.test(text) ? 'map' : /id card studio/.test(text) ? 'home' : /picture|photo|capture|camera/.test(text) && !/folder/.test(text) ? 'photo' : /folder/.test(text) ? 'folder' : /spreadsheet/.test(text) ? 'sheet' : /^add|^new/.test(text) ? 'add' : /^edit/.test(text) ? 'edit' : /^delete/.test(text) ? 'delete' : /^save|update/.test(text) ? 'save' : /cancel|close/.test(text) ? 'cancel' : /search|find/.test(text) ? 'search' : /download/.test(text) ? 'download' : /connect|change|open|select/.test(text) ? 'connect' : 'generic';
      button.classList.add('studio-icon-button');
      button.dataset.studioAction = action;
      button.dataset.studioIcon = button.querySelector('svg') ? '' : symbols[action];
    });
  }
  function installStudioLayout() {
    if (!['student', 'staff', 'custom'].includes(STUDIO_TYPE)) return;
    const sources = document.getElementById(STUDIO_TYPE + 'DataSources');
    if (sources) {
      const tools = document.createElement('div');
      tools.className = 'studio-data-tools';
      const actions = document.createElement('div');
      actions.className = 'studio-data-actions';
      const clear = document.createElement('button');
      clear.type = 'button';
      clear.className = 'studio-nav-button clear-local';
      clear.textContent = 'Clear Data';
      clear.title = 'Reset this studio’s saved design, mappings, and cached photos. Spreadsheet records and photo files are kept.';
      clear.onclick = clearLocalData;
      const refresh = document.createElement('button');
      refresh.type = 'button';
      refresh.className = 'studio-nav-button refresh-records';
      refresh.textContent = 'Refresh Data';
      refresh.title = 'Reload spreadsheet records and photos from the connected sources.';
      refresh.onclick = () => refreshRecordsAndPhotos(refresh);
      actions.append(clear, refresh);
      const help = document.createElement('p');
      help.className = 'source-note';
      const clearHelp = document.createElement('span');
      clearHelp.textContent = 'Clear Data: reset saved design, mappings, and cached photos. Spreadsheet records and photo files are kept.';
      const refreshHelp = document.createElement('span');
      refreshHelp.textContent = 'Refresh Data: reload records and photos from your connected sources.';
      help.append(clearHelp, refreshHelp);
      tools.append(actions, help);
      const summary = sources.querySelector('summary');
      if (summary) summary.after(tools);else sources.insertBefore(tools, sources.firstChild);
    }
    const preview = document.getElementById(STUDIO_TYPE === 'student' ? 'previewAllStudentsButton' : STUDIO_TYPE === 'staff' ? 'previewAllStaffButton' : 'previewAllCustomButton');
    const head = preview && preview.closest('.preview-head, .preview-toolbar');
    if (head) {
      head.classList.add('unified-preview-header');
      const description = head.querySelector('p');
      if (description) description.after(preview);
      const prints = document.createElement('div');
      prints.className = 'studio-print-actions';
      const printButtons = Array.from(head.querySelectorAll('button[id^="print"]'));
      printButtons.sort((a, b) => Number(a.id.startsWith('printAll')) - Number(b.id.startsWith('printAll')));
      printButtons.forEach(button => {
        button.textContent = button.id.startsWith('printAll') ? 'Print All Cards' : 'Print Displayed Cards';
        prints.appendChild(button);
      });
      head.appendChild(prints);
      Array.from(head.children).forEach(child => {
        if (child !== prints && child.tagName === 'DIV' && !child.children.length) child.remove();
      });
      const count = document.createElement('p');
      count.id = 'studioCardCount';
      count.className = 'studio-card-count';
      count.setAttribute('aria-live', 'polite');
      head.before(count);
      const mount = document.getElementById(STUDIO_TYPE === 'student' ? 'cardsWrapper' : 'cardMount');
      let scheduled = false;
      function updateCount() {
        scheduled = false;
        const countShown = mount.querySelectorAll('.album-design-card[data-record-id]:not([data-record-id=""])').length;
        const text = countShown + ' card' + (countShown === 1 ? '' : 's') + ' shown · ' + currentRecords().length + ' records';
        if (count.textContent !== text) count.textContent = text;
      }
      new MutationObserver(() => {
        if (!scheduled) {
          scheduled = true;
          requestAnimationFrame(updateCount);
        }
      }).observe(mount, {
        childList: true,
        subtree: true
      });
      updateCount();
    }
    // Legacy element IDs remain hidden for compatibility with status updates.
    const designButton = document.getElementById(STUDIO_TYPE === 'student' ? 'setupDesignButton' : STUDIO_TYPE + 'DesignButton');
    if (designButton) {
      const block = designButton.parentElement;
      block.classList.add('legacy-design-choice');
      const design = STUDIO_TYPE === 'student' ? activeCardDesign : STUDIO_TYPE === 'staff' ? activeStaffDesign : activeCustomDesign;
      const mappingNote = document.getElementById(STUDIO_TYPE + 'MappingNote');
      if (mappingNote && design) mappingNote.textContent = 'Selected: ' + (design.selectedFileName || design.name) + '. Open Design Mapping to change the design or column links.';
    }
  }
  function installButtonIcons() {
    if (!['student', 'staff', 'custom', 'design'].includes(STUDIO_TYPE)) return;
    decorateButtons(document);
    let iconsScheduled = false;
    new MutationObserver(() => {
      if (!iconsScheduled) {
        iconsScheduled = true;
        requestAnimationFrame(() => {
          iconsScheduled = false;
          decorateButtons(document);
        });
      }
    }).observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true
    });
  }
  window.addEventListener('DOMContentLoaded', installStudioLayout);
  window.addEventListener('DOMContentLoaded', installButtonIcons);
  function carryDesignToScope(scope) {
    if (!scope || scope === STUDIO_SCOPE) return;
    Object.keys(localStorage).filter(key => key.startsWith(STUDIO_SCOPE) && (key.slice(STUDIO_SCOPE.length).startsWith('active_') || key.slice(STUDIO_SCOPE.length).startsWith('id_card_column_mapping_'))).forEach(key => localStorage.setItem(scope + key.slice(STUDIO_SCOPE.length), localStorage.getItem(key)));
  }
  return {
    carryDesignToScope: carryDesignToScope,
    openDesignMapping: openDesignMapping,
    refreshRecordsAndPhotos: refreshRecordsAndPhotos,
    call: call,
    photo: photo,
    photoStates: photoStates,
    invalidate: invalidate,
    registerPopup: registerPopup,
    reopen: reopen
  };
}();
</script>
`;

    case 'Staff':
      return `<!DOCTYPE html>
<html>
<head>
<script>
window.STUDIO_URL = <?!= JSON.stringify(webAppUrl) ?>;
window.STUDIO_TYPE = <?!= JSON.stringify(studioType) ?>;
window.STUDIO_SCOPE = <?!= JSON.stringify(clientScope) ?>;
window.STUDIO_STORAGE = {
  getItem: function (k) {
    return localStorage.getItem(STUDIO_SCOPE + k);
  },
  setItem: function (k, v) {
    localStorage.setItem(STUDIO_SCOPE + k, v);
  },
  removeItem: function (k) {
    localStorage.removeItem(STUDIO_SCOPE + k);
  }
};
</script>
<base target="_top">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {
  --primary: #7141c6;
  --primary-dark: #58309f;
  --ink: #172033;
  --muted: #667085;
  --line: #dce3ec;
  --green: #1f883d;
}
* {
  box-sizing: border-box;
}
[hidden] {
  display: none !important;
}
body {
  min-height: 100vh;
  margin: 0;
  padding: 24px;
  font-family: "Segoe UI", Arial, sans-serif;
  color: var(--ink);
  background: linear-gradient(135deg, #f8f6fc, #edf1f7);
}
input, select, button {
  font: inherit;
}
input[type="file"] {
  display: none;
}
.setup-screen {
  min-height: calc(100vh - 48px);
  display: grid;
  place-items: center;
}
.setup-card {
  width: 100%;
  max-width: 560px;
  padding: 30px;
  background: rgba(255,255,255,.98);
  border: 1px solid var(--line);
  border-radius: 18px;
  box-shadow: 0 20px 50px rgba(33,48,73,.13);
}
.mark {
  width: 50px;
  height: 50px;
  display: grid;
  place-items: center;
  color: #fff;
  background: linear-gradient(135deg, var(--primary), #9b66e8);
  border-radius: 14px;
  font-weight: 800;
}
.mark svg {
  width: 35px;
  height: 35px;
  display: block;
  filter: drop-shadow(0 2px 3px rgba(23,32,51,.24));
}
h1 {
  margin: 14px 0 6px;
  font-size: 25px;
}
.intro {
  margin: 0 0 22px;
  color: var(--muted);
  line-height: 1.5;
  font-size: 14px;
}
.field {
  margin-bottom: 14px;
}
label {
  display: block;
  margin-bottom: 5px;
  font-size: 12px;
  font-weight: 750;
}
.input {
  width: 100%;
  min-height: 38px;
  padding: 8px 11px;
  color: var(--ink);
  background: #fff;
  border: 1px solid #cfd7e2;
  border-radius: 8px;
  outline: none;
}
.input:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(113,65,198,.14);
}
.note {
  margin: 5px 0 0;
  color: var(--muted);
  font-size: 11px;
}
.btn {
  min-height: 38px;
  padding: 8px 12px;
  color: #fff;
  background: var(--primary);
  border: 0;
  border-radius: 8px;
  font-weight: 750;
  cursor: pointer;
}
.btn:hover {
  background: var(--primary-dark);
}
.btn:disabled {
  opacity: .6;
  cursor: wait;
}
.btn.secondary {
  color: #344054;
  background: #eef1f5;
}
.btn.green {
  background: var(--green);
}
.btn.orange {
  background: #e67e22;
}
.btn.brown {
  background: #8b4513;
}
.full {
  width: 100%;
}
.button-pair {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 9px;
}
.setup-status {
  min-height: 20px;
  margin: 10px 0 0;
  color: #b42318;
  font-size: 13px;
  font-weight: 650;
}
.home-link {
  display: inline-block;
  margin-top: 14px;
  color: var(--primary);
  text-decoration: none;
  font-size: 13px;
  font-weight: 700;
}
.app-header {
  width: 100%;
  max-width: none;
  margin: 0 auto 18px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 11px;
}
.brand .mark {
  width: 44px;
  height: 44px;
}
.brand h1 {
  margin: 0;
  font-size: 21px;
}
.brand p {
  margin: 3px 0 0;
  color: var(--muted);
  font-size: 12px;
}
.header-actions {
  display: flex;
  gap: 8px;
}
.header-btn {
  padding: 7px 11px;
  color: #344054;
  background: #fff;
  border: 1px solid var(--line);
  border-radius: 999px;
  text-decoration: none;
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
}
.header-btn.id-studio-link {
  display: inline-flex;
  align-items: center;
  color: #fff;
  background: #17233a;
  border-color: #17233a;
  border-radius: 9px;
}
.header-btn.id-studio-link:hover {
  color: #fff;
  background: #101a2c;
  border-color: #101a2c;
}
.workspace {
  width: 100%;
  max-width: none;
  min-height: calc(100vh - 110px);
  margin: 0 auto;
  display: grid;
  grid-template-columns: 350px 1fr;
  gap: 18px;
}
.panel {
  background: rgba(255,255,255,.97);
  border: 1px solid var(--line);
  border-radius: 14px;
  box-shadow: 0 10px 30px rgba(33,48,73,.08);
}
.controls {
  height: max-content;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.control-section {
  padding: 15px 16px;
  border-bottom: 1px solid #edf0f4;
}
.control-section:last-child {
  border-bottom: 0;
}
.data-sources-panel {
  order: 99;
  border-top: 1px solid #edf0f4;
  border-bottom: 0;
}
.data-sources-panel > summary {
  margin: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  list-style: none;
  cursor: pointer;
  user-select: none;
}
.data-sources-panel > summary::-webkit-details-marker {
  display: none;
}
.data-sources-panel > summary::after {
  content: '+';
  width: 23px;
  height: 23px;
  display: grid;
  place-items: center;
  flex: 0 0 23px;
  color: var(--primary);
  background: #f2edfc;
  border-radius: 6px;
  font-size: 17px;
  line-height: 1;
}
.data-sources-panel[open] > summary {
  margin-bottom: 11px;
}
.data-sources-panel[open] > summary::after {
  content: '−';
}
.source-sheet-button {
  background: #185adb !important;
}
.source-sheet-button:hover {
  background: #1248b5 !important;
}
.source-folder-button {
  background: #0f8b8d !important;
}
.source-folder-button:hover {
  background: #0b7173 !important;
}
.source-design-button {
  background: #7141c6 !important;
}
.source-design-button:hover {
  background: #58309f !important;
}
.section-title {
  margin: 0 0 11px;
  color: #475467;
  font-size: 11px;
  font-weight: 800;
  letter-spacing: .08em;
  text-transform: uppercase;
}
.source-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.source-row .input {
  min-width: 0;
  flex: 1;
}
.source-row .btn {
  width: auto;
  flex: 0 0 auto;
}
.stack {
  display: flex;
  flex-direction: column;
  gap: 9px;
}
.search-row {
  display: flex;
  gap: 8px;
}
.search-row .input {
  min-width: 0;
}
.search-row .btn {
  flex: 0 0 auto;
}
.action-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 9px;
}
.action-grid .btn.wide {
  grid-column: 1 / -1;
}
.preview {
  overflow: hidden;
}
.preview-head {
  padding: 14px 18px;
  background: #fff;
  border-bottom: 1px solid var(--line);
}
.preview-head h2 {
  margin: 0;
  font-size: 16px;
}
.preview-head p {
  margin: 3px 0 0;
  color: var(--muted);
  font-size: 12px;
}
.preview-canvas {
  min-height: calc(100vh - 174px);
  padding: 35px;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  background-color: #e9e5f1;
  background-image: radial-gradient(rgba(113,65,198,.12) 1px, transparent 1px);
  background-size: 18px 18px;
}
#cardMount.previewing-all {
  width: 100%;
}
.all-card-preview-grid {
  width: 100%;
  display: flex;
  flex-wrap: wrap;
  align-items: flex-start;
  justify-content: center;
  gap: 24px;
}
.all-card-preview-status {
  width: 100%;
  margin: 0 0 18px;
  color: #475467;
  font-size: 12px;
  font-weight: 750;
  text-align: center;
}
.staff-card {
  width: 204px;
  height: 324px;
  padding: 8px;
  display: flex;
  flex-direction: column;
  align-items: center;
  overflow: hidden;
  color: #111827;
  background: #fff;
  border: 1px solid #cfd7e2;
  border-radius: 12px;
  box-shadow: 0 12px 26px rgba(23,32,51,.17);
}
.card-header {
  width: 100%;
  height: 76px;
  padding: 16px 0 0;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  flex: 0 0 76px;
  overflow: hidden;
  border-bottom: 1px solid #e5e7eb;
}
.lanyard-slot {
  width: 56px;
  height: 12px;
  position: absolute;
  top: 2px;
  left: 50%;
  transform: translateX(-50%);
  border: 1px dashed #a8b0b8;
  border-radius: 8px;
}
.card-logo {
  width: 100%;
  height: 100%;
  max-width: 188px;
  max-height: 60px;
  object-fit: contain;
}
.staff-photo-frame {
  width: 116px;
  height: 140px;
  margin: 7px 0 6px;
  flex: 0 0 140px;
  display: grid;
  place-items: center;
  overflow: hidden;
  color: var(--muted);
  background: #f4f5f7;
  border: 1px dashed var(--primary);
  border-radius: 9px;
  font-size: 9px;
  font-weight: 700;
}
.staff-photo {
  width: 100%;
  height: 100%;
  object-fit: cover;
}
.staff-details {
  width: 100%;
  min-height: 0;
  text-align: center;
}
.staff-first, .staff-last {
  max-width: 100%;
  overflow: hidden;
  color: #111827;
  font-size: 17px;
  font-weight: 850;
  line-height: 1.05;
  text-overflow: ellipsis;
  text-transform: uppercase;
  white-space: nowrap;
}
.staff-title {
  max-width: 100%;
  margin-top: 6px;
  overflow: hidden;
  color: #ff0000 !important;
  font-size: 12px;
  font-weight: 800;
  line-height: 1.15;
  text-overflow: ellipsis;
  text-transform: uppercase;
  white-space: nowrap;
}
.staff-year {
  margin-top: 5px;
  color: #0000ff !important;
  font-size: 12px;
  font-weight: 900 !important;
  letter-spacing: .04em;
}
.staff-title, .staff-year {
  -webkit-print-color-adjust: exact !important;
  print-color-adjust: exact !important;
}
.modal {
  position: fixed;
  inset: 0;
  z-index: 1000;
  padding: 18px;
  display: grid;
  place-items: center;
  background: rgba(15,23,42,.66);
}
.modal-card {
  width: 100%;
  max-width: 460px;
  max-height: calc(100vh - 36px);
  padding: 22px;
  overflow: auto;
  background: #fff;
  border-radius: 14px;
  box-shadow: 0 22px 60px rgba(0,0,0,.3);
}
.modal-card h2 {
  margin: 0 0 17px;
}
.modal-actions {
  display: flex;
  gap: 9px;
  margin-top: 16px;
}
.modal-actions .btn {
  flex: 1;
}
#saveStaffButton {
  order: 1;
}
#deleteStaffButton {
  order: 2;
}
#addStaffModal .modal-actions .secondary {
  order: 3;
}
.camera-frame {
  width: 270px;
  height: 340px;
  max-width: 100%;
  margin: 12px auto;
  overflow: hidden;
  background: #101010;
  border-radius: 10px;
}
.camera-frame video, .camera-frame img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}
.status {
  min-height: 18px;
  margin: 9px 0 0;
  color: #b42318;
  font-size: 12px;
  font-weight: 650;
}
@media (max-width: 760px) {
  body {
    padding: 14px;
  }
  .workspace {
    grid-template-columns: 1fr;
    min-height: 0;
  }
  .preview-canvas {
    min-height: 410px;
    padding: 28px 12px;
  }
  .app-header {
    align-items: flex-start;
  }
  .brand p {
    display: none;
  }
}
@media print {
  @page {
    size: auto;
    margin: 0;
  }
  body {
    padding: 0 !important;
    margin: 0 !important;
    background: transparent !important;
    print-color-adjust: exact;
  }
  .app-header, .controls, .preview-head, .modal, .all-card-preview-status {
    display: none !important;
  }
  .workspace, .preview, .preview-canvas {
    width: auto !important;
    min-height: 0 !important;
    padding: 0 !important;
    margin: 0 !important;
    display: block !important;
    background: transparent !important;
    border: 0 !important;
    box-shadow: none !important;
  }
  .staff-card {
    width: 53.98mm !important;
    height: 85.60mm !important;
    padding: .083in !important;
    border: 0 !important;
    border-radius: 0 !important;
    box-shadow: none !important;
  }
  .lanyard-slot {
    border-color: transparent !important;
  }
}

/* Match Student Studio's compact name search. */
.name-search-wrapper {position:relative;width:100%;display:flex;align-items:center;}
.name-search-wrapper .name-search-input {width:100%;min-width:0;height:38px;min-height:38px;padding:8px 38px 8px 11px;font:13px "Segoe UI",Arial,sans-serif;border:1px solid #d0d7de;border-radius:8px;background:#fff;outline:none;box-sizing:border-box;}
.name-search-wrapper .name-search-input:focus {border-color:#0969da;box-shadow:0 0 0 2px rgba(9,105,218,.2);}
.name-search-wrapper .search-btn {position:absolute;right:4px;top:50%;transform:translateY(-50%);width:30px;height:30px;min-height:30px;padding:4px;display:flex;align-items:center;justify-content:center;color:#57606a;background:none;border:none;border-radius:4px;cursor:pointer;}
.name-search-wrapper .search-btn:hover {color:#0969da;background:#f3f4f6;}
.name-search-wrapper .search-btn:focus-visible {outline:2px solid #0969da;outline-offset:1px;}
.name-search-wrapper .search-btn::before {display:none!important;}
</style>
</head>
<body>
<header id="appHeader" class="app-header">
<div class="brand">
<div class="mark" role="img" aria-label="Staff">
<svg viewBox="0 0 48 48" aria-hidden="true">
<path d="M10 42c.8-9 5.8-14 14-14s13.2 5 14 14" fill="#233c78"/>
<path d="M19 29l5 6 5-6" fill="#fff"/>
<path d="M23 34h2l2 8h-6l2-8z" fill="#ff5c70"/>
<circle cx="24" cy="19" r="8" fill="#f2b88f"/>
<path d="M16 18c.5-8 15-10 17-2-4-1-8-2-12-4-1 3-3 5-5 6z" fill="#51362b"/>
<rect x="31" y="30" width="10" height="8" rx="2" fill="#ffd34e"/>
<circle cx="34" cy="33" r="1.5" fill="#7141c6"/>
<path d="M37 33h2M34 36h5" stroke="#7141c6" stroke-width="1.3" stroke-linecap="round"/>
</svg>
</div>
<div>
<h1>Staff ID Card Studio</h1>
<p>Find staff members, manage records and photos, and print cards using your selected design.</p>
</div>
</div>
<div class="header-actions">
<a class="header-btn id-studio-link" href="<?!= webAppUrl ?>" target="_top">← ID Card Studio</a>
</div>
</header>
<main id="workspace" class="workspace">
<aside class="panel controls">
<details id="staffDataSources" class="control-section data-sources-panel">
<summary class="section-title">Data Sources</summary>
<p class="note">Connect a spreadsheet to open Design Mapping. Choose a design, worksheet, header option, and columns together. Internal record and photo columns are reused when you change designs.</p>
<div class="field">
<label for="staffSpreadsheetUrl">Staff Spreadsheet</label>
<div class="source-row">
<input id="staffSpreadsheetUrl" class="input" type="text" placeholder="Paste Google Spreadsheet URL or ID">
<button id="connectStaffSpreadsheetButton" class="btn source-sheet-button" type="button" onclick="connectStaffSpreadsheet()">Connect</button>
</div>
<p id="sheetNote" class="note">No staff spreadsheet connected yet.</p>
</div>
<div class="field">
<label for="staffPhotoFolderUrl">Staff Photo Folder</label>
<div class="source-row">
<input id="staffPhotoFolderUrl" class="input" type="text" placeholder="Paste Google Drive folder URL or ID">
<button id="connectStaffFolderButton" class="btn source-folder-button" type="button" onclick="connectStaffPhotoFolder()">Connect</button>
</div>
<p id="folderNote" class="note">Photo filenames must match the staff full name, for example Alex Smith.jpg.</p>
</div>
<div class="field">
<label>Staff Card Design</label>
<input id="staffDesignFile" type="file" accept=".json,application/json" onchange="selectStaffCardDesign(event)">
<button id="staffDesignButton" class="btn full source-design-button" type="button" onclick="openStaffColumnMapping()" title="Choose a saved Design Studio .json file from your device.">Select Card Design</button>
<p id="staffDesignNote" class="note">Choose a .json design file saved in Design Studio, then map its data elements below.</p>
</div>
<div class="field">
<label>Design Mapping</label>
<button id="staffMappingButton" class="btn full" style="background:#d97706" type="button" onclick="openStaffColumnMapping()" title="Choose which spreadsheet column supplies each data element in this design.">Design Mapping</button>
<p id="staffMappingNote" class="note">Connect a spreadsheet, select a design, then match its data elements to spreadsheet columns.</p>
</div>
<p id="setupStatus" class="setup-status" role="status">
</p>
</details>
<section class="control-section">
<h2 class="section-title">Find Staff</h2>
<div class="stack">
<div class="name-search-wrapper">
<input id="staffSearchInput" class="name-search-input" type="search" placeholder="Search by Staff Name" aria-label="Search by Staff Name" autocomplete="off" onkeydown="if(event.key==='Enter'){event.preventDefault();searchStaffByName()}">
<button class="search-btn" type="button" onclick="searchStaffByName()" title="Search by Staff Name" aria-label="Search by Staff Name">
<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
</button>
</div>
<select id="staffSelect" class="input" onchange="selectStaff(this.value)">
<option value="">Select Staff Member</option>
</select>
</div>
</section>
<section class="control-section">
<h2 class="section-title">Actions</h2>
<div class="action-grid">
<button class="btn" style="background:#1f883d" type="button" onclick="openAddStaff()" title="Add a staff member using the fields mapped in your selected design.">Add Staff</button>
<button class="btn" style="background:#7141c6" type="button" onclick="openEditStaff()" title="Change or delete the selected staff member.">Edit Staff</button>
<button class="btn wide" style="background:#d97706" type="button" onclick="openCamera()" title="Open the camera for the selected record. Capture, review, and save a photo.">Take Photo</button>
</div>
</section>
<section class="control-section">
<h2 class="section-title">Data</h2>
<div class="action-grid">
<button class="btn" style="background:#185adb" type="button" onclick="openSavedResource('spreadsheet')" title="Open the connected spreadsheet in a new tab. Return here to reload saved changes.">Open the Spreadsheet</button>
<button class="btn" style="background:#0f8b8d" type="button" onclick="openSavedResource('folder')" title="Open the connected Google Drive photo folder in a new tab.">Open the Photo Folder</button>
</div>
</section>
</aside>
<section class="panel preview">
<div class="preview-head" style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
<div>
<h2>Staff ID Card Preview</h2>
<p>Search by any part of a name to preview all matches, select one staff member, or preview all staff cards. Print displayed cards or all cards, then choose Front Side, Back Side, or both in print preview.</p>
</div>
<div style="display:flex;align-items:center;justify-content:flex-end;gap:9px;flex-wrap:wrap">
<button id="previewAllStaffButton" class="btn" style="background:#7141c6" type="button" onclick="previewAllStaffCards()" title="Display all records using the selected design. This does not print.">Preview All Staff ID Cards</button>
<button id="printSelectedStaffButton" class="btn" style="background:#b42318" type="button" onclick="CardDesignRuntime.printCards(document.getElementById('cardMount'),{title:'Selected Staff ID Card'})" title="Print the displayed search results or selected record and choose the card side.">Print Displayed Staff ID Cards</button>
<button id="printAllStaffButton" class="btn" style="background:#185adb" type="button" onclick="printAllStaffCards()" title="Prepare all records for printing, then choose the card side in print preview.">Print All Staff ID Cards</button>
</div>
</div>
<div class="preview-canvas">
<div id="cardMount">
</div>
</div>
</section>
</main>
<div id="addStaffModal" class="modal" hidden>
<form class="modal-card" onsubmit="saveNewStaff(event)">
<h2 id="staffModalTitle">Add Staff Member</h2>
<p class="note">These fields come from the mapped data elements on both sides of your selected design. Save writes the values to the connected staff spreadsheet.</p>
<div id="staffDesignLinkedFields">
</div>
<div class="modal-actions">
<button id="saveStaffButton" class="btn green" type="submit" title="Save the entered values to the connected spreadsheet.">Save</button>
<button id="deleteStaffButton" class="btn" style="background:#b42318" type="button" onclick="deleteCurrentStaff()" hidden title="Delete this spreadsheet record and move matching photos to Drive Trash.">Delete</button>
<button class="btn secondary" type="button" onclick="closeAddStaff()" title="Close without saving these changes.">Cancel</button>
</div>
<p id="addStaffStatus" class="status">
</p>
</form>
</div>
<div id="cameraModal" class="modal" hidden>
<div class="modal-card">
<h2>Take Staff Photo</h2>
<select id="cameraSelect" class="input" onchange="startCamera(this.value)">
<option value="">Loading cameras...</option>
</select>
<div class="camera-frame">
<video id="cameraVideo" autoplay playsinline muted>
</video>
<img id="cameraPreview" alt="Captured staff photo" hidden>
</div>
<div class="modal-actions">
<button id="captureButton" class="btn" type="button" onclick="capturePhoto()" title="Capture the current camera image for review.">Capture</button>
<button id="retakeButton" class="btn orange" type="button" onclick="retakePhoto()" hidden title="Discard the captured image and return to the camera.">Retake</button>
<button id="savePhotoButton" class="btn green" type="button" onclick="saveCapturedPhoto()" disabled title="Save the entered values to the connected spreadsheet.">Save</button>
<button class="btn secondary" type="button" onclick="closeCamera()" title="Close without saving these changes.">Cancel</button>
</div>
<p id="cameraStatus" class="status">
</p>
</div>
</div>
<?!= include('DesignRuntime'); ?>
<script>
const STAFF_LOGO_KEY = 'staff_card_logo';
const STAFF_ACTIVE_DESIGN_KEY = 'active_staff_card_design';
let configuration = {
  hasSpreadsheet: false,
  hasPhotoFolder: false
};
let staffRecords = [];
let staffSpreadsheetHeaders = [];
let activeStaffId = '';
let logoData = '';
let activeStaffDesign = null;
let staffColumnMap = {};
let cameraStream = null;
let capturedPhoto = '';
let staffCameraWindow = null;
let cameraTargetStaffId = '';
let cameraTargetStaffName = '';
let editingStaffId = '';
let staffPreviewRequest = 0;
window.addEventListener('DOMContentLoaded', function () {
  logoData = STUDIO_STORAGE.getItem(STAFF_LOGO_KEY) || '';
  activeStaffDesign = loadStaffDesign();
  syncStaffColumnMapping();
  google.script.run.withSuccessHandler(function (result) {
    configuration = result || configuration;
    updateSetupState();
    if (configuration.hasSpreadsheet) {
      google.script.run.withSuccessHandler(populateStaff).withFailureHandler(showSetupError).getStaffData();
    } else {
      populateStaff([]);
    }
  }).withFailureHandler(showSetupError).getStaffConfiguration();
});
function updateSetupState() {
  if (configuration.hasSpreadsheet) {
    document.getElementById('staffSpreadsheetUrl').placeholder = 'Paste another URL or ID to change it';
    document.getElementById('sheetNote').textContent = 'Staff spreadsheet connected. Saved changes reload when you return to this studio.';
    document.getElementById('sheetNote').style.color = '#1f883d';
    document.getElementById('connectStaffSpreadsheetButton').textContent = 'Change';
  } else {
    document.getElementById('sheetNote').textContent = 'No staff spreadsheet connected yet.';
    document.getElementById('sheetNote').style.color = '#b42318';
    document.getElementById('connectStaffSpreadsheetButton').textContent = 'Connect';
  }
  if (configuration.hasPhotoFolder) {
    document.getElementById('staffPhotoFolderUrl').placeholder = 'Paste another URL or ID to change it';
    document.getElementById('folderNote').textContent = 'Staff photo folder connected. Photos keep friendly full-name filenames and are linked to stable internal records.';
    document.getElementById('folderNote').style.color = '#1f883d';
    document.getElementById('connectStaffFolderButton').textContent = 'Change';
  } else {
    document.getElementById('folderNote').textContent = 'No staff photo folder connected yet.';
    document.getElementById('folderNote').style.color = '#b42318';
    document.getElementById('connectStaffFolderButton').textContent = 'Connect';
  }
  if (activeStaffDesign) {
    document.getElementById('staffDesignButton').textContent = 'Selected: ' + (activeStaffDesign.selectedFileName || activeStaffDesign.name);
    document.getElementById('staffDesignNote').textContent = 'Select this button to choose a different .json design file. Review its column mapping before use.';
    document.getElementById('staffDesignNote').style.color = '#1f883d';
  } else {
    document.getElementById('staffDesignButton').textContent = 'Select Card Design';
    document.getElementById('staffDesignNote').textContent = 'Choose a .json design file saved in Design Studio, then map its data elements below.';
    document.getElementById('staffDesignNote').style.color = '#667085';
  }
  if (!configuration.hasSpreadsheet || !configuration.hasPhotoFolder || !activeStaffDesign) {
    document.getElementById('staffDataSources').open = true;
  }
  updateStaffMappingState();
}
function normalizeSelectedCardDesign(design, fileName) {
  if (!design || design.fileType !== 'ID_CARD_DESIGN' || !Array.isArray(design.elements) && !Array.isArray(design.frontElements) && !Array.isArray(design.backElements)) return null;
  design.frontElements = Array.isArray(design.frontElements) ? design.frontElements : Array.isArray(design.elements) ? design.elements : [];
  design.backElements = Array.isArray(design.backElements) ? design.backElements : [];
  design.elements = design.frontElements;
  design.dataSource = 'staff';
  if (fileName && fileName !== 'ID Card Design') design.selectedFileName = fileName;
  if (!String(design.name || '').trim()) {
    design.name = String(fileName || '').replace(/\\.json$/i, '') || 'ID Card Design';
  }
  return design;
}
function loadStaffDesign() {
  try {
    const design = JSON.parse(STUDIO_STORAGE.getItem(STAFF_ACTIVE_DESIGN_KEY) || 'null');
    return normalizeSelectedCardDesign(design, 'ID Card Design');
  } catch (error) {
    return null;
  }
}
function syncStaffColumnMapping() {
  staffColumnMap = activeStaffDesign ? CardDesignRuntime.loadColumnMapping(activeStaffDesign, 'staff') : {};
  if (activeStaffDesign) CardDesignRuntime.applyColumnMapping(activeStaffDesign, staffColumnMap);
  updateStaffMappingState();
}
function updateStaffMappingState() {
  const button = document.getElementById('staffMappingButton');
  const note = document.getElementById('staffMappingNote');
  if (!button || !note) return;
  button.disabled = false;
  button.textContent = 'Design Mapping';
  note.textContent = 'Select a design, worksheet, header option, and columns together.';
}

function openStaffColumnMapping(onlyIfNeeded) {
  StudioReliability.openDesignMapping({
    design: activeStaffDesign
  });
}
function staffMappedValue(record, type, fallbackValue) {
  if (activeStaffDesign && record) {
    const value = CardDesignRuntime.getLinkedValue(activeStaffDesign, record, type);
    if (String(value || '').trim()) return String(value).trim();
  }
  return String(fallbackValue == null ? '' : fallbackValue).trim();
}
function staffDropdownName(record) {
  record = record || {};
  const first = staffMappedValue(record, 'firstName', record.firstName);
  const middle = staffMappedValue(record, 'middleName', record.middleName);
  const last = staffMappedValue(record, 'lastName', record.lastName);
  const full = staffMappedValue(record, 'fullName', record.fullName);
  const parts = [first, middle, last].filter(Boolean).join(' ');
  return first && last ? parts : full || parts || 'Unnamed Record';
}
function staffMappedFullName(record) {
  return CardDesignRuntime.recordLabel(activeStaffDesign, record || {});
}
function selectStaffCardDesign(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function (loadEvent) {
    try {
      const design = normalizeSelectedCardDesign(JSON.parse(loadEvent.target.result), file.name);
      if (!design) throw new Error('Choose a .json design file saved by Design Studio.');
      activeStaffDesign = design;
      STUDIO_STORAGE.setItem(STAFF_ACTIVE_DESIGN_KEY, JSON.stringify(design));
      syncStaffColumnMapping();
      updateSetupState();
      document.getElementById('setupStatus').textContent = '';
      const index = document.getElementById('staffSelect').value;
      if (index !== '' && staffRecords[index]) renderStaffCard(staffRecords[index]);else renderEmptyStaffCard();
      openStaffColumnMapping(true);
    } catch (error) {
      showSetupError(error);
    }
  };
  reader.readAsText(file);
  event.target.value = '';
}

/* Removes empty transparent or white space around the logo artwork. */

function showSetupError(error) {
  const status = document.getElementById('setupStatus');
  status.style.color = '#b42318';
  status.textContent = error && error.message ? error.message : String(error);
}
function connectStaffSpreadsheet() {
  const input = document.getElementById('staffSpreadsheetUrl');
  const url = input.value.trim();
  if (!url) {
    alert('Enter a spreadsheet URL or ID first.');
    return;
  }
  StudioReliability.openDesignMapping({
    spreadsheetUrl: url,
    design: activeStaffDesign
  });
}
function connectStaffPhotoFolder() {
  const input = document.getElementById('staffPhotoFolderUrl');
  const folderUrl = input.value.trim();
  const button = document.getElementById('connectStaffFolderButton');
  const status = document.getElementById('setupStatus');
  if (!folderUrl) return showSetupError('Please paste the Staff Photo Folder URL or ID.');
  button.disabled = true;
  status.style.color = '#667085';
  status.textContent = 'Connecting staff photo folder...';
  google.script.run.withSuccessHandler(function (result) {
    StudioReliability.carryDesignToScope(result && result.scope);
    button.disabled = false;
    input.value = '';
    configuration.hasPhotoFolder = true;
    updateSetupState();
    status.style.color = '#1f883d';
    status.textContent = 'Staff photo folder connected successfully.';
    StudioReliability.reopen();
    return;
  }).withFailureHandler(function (error) {
    button.disabled = false;
    showSetupError('Photo folder not changed: ' + (error.message || String(error)));
  }).setStaffPhotoFolderUrl(folderUrl);
}
function openSavedResource(resourceType) {
  const newTab = window.open('about:blank', '_blank');
  if (!newTab) {
    alert('Allow pop-ups for this app, then open the spreadsheet or photo folder again.');
    return;
  }
  google.script.run.withSuccessHandler(function (url) {
    newTab.location.href = url;
  }).withFailureHandler(function (error) {
    newTab.close();
    alert(error.message || String(error));
  }).getConfiguredResourceUrl('staff', resourceType);
}
function populateStaff(records, preferredRecordKey) {
  staffRecords = records || [];
  updateStaffMappingState();
  if (staffRecords.length && Array.isArray(staffRecords[0]._headers)) {
    staffSpreadsheetHeaders = staffRecords[0]._headers.slice();
  } else if (configuration.hasSpreadsheet) {
    google.script.run.withSuccessHandler(function (headers) {
      staffSpreadsheetHeaders = Array.isArray(headers) ? headers : [];
      updateStaffMappingState();
    }).withFailureHandler(function () {
      staffSpreadsheetHeaders = [];
    }).getConfiguredSpreadsheetHeaders('staff');
  }
  const select = document.getElementById('staffSelect');
  select.innerHTML = '<option value="">Select Staff Member</option>';
  staffRecords.forEach(function (staff, index) {
    const option = document.createElement('option');
    option.value = String(index);
    const displayName = staffDropdownName(staff);
    const displayTitle = staffMappedValue(staff, 'title', staff.title) || staffMappedValue(staff, 'department', staff.department);
    option.textContent = displayName + (displayTitle ? ' (' + displayTitle + ')' : '');
    select.appendChild(option);
  });
  const requestedKey = String(preferredRecordKey || '');
  if (staffRecords.length && requestedKey) {
    const preferredIndex = staffRecords.findIndex(function (staff) {
      return String(staff.recordKey || '') === requestedKey;
    });
    if (preferredIndex !== -1) {
      select.value = String(preferredIndex);
      selectStaff(String(preferredIndex));
      return;
    }
  }
  select.value = '';
  activeStaffId = '';
  renderEmptyStaffCard();
}
function selectStaff(index) {
  window.activeNameSearch = '';
  if (index === '' || !staffRecords[index]) {
    activeStaffId = '';
    renderEmptyStaffCard();
    return;
  }
  const staff = staffRecords[index];
  activeStaffId = String(staff.recordKey || '');
  renderStaffCard(staff);
}
function searchStaffByName() {
  const input = document.getElementById('staffSearchInput');
  const query = input.value.trim();
  if (!query) return;
  const matches = CardDesignRuntime.matchingRecords(activeStaffDesign, staffRecords, query, false);
  if (!matches.length) {
    alert('No matching records were found for: ' + query);
    return;
  }
  const select = document.getElementById('staffSelect');
  select.value = '';
  activeStaffId = '';
  if (matches.length === 1) {
    select.value = String(staffRecords.indexOf(matches[0]));
    selectStaff(select.value);
  } else previewAllStaffCards(matches);
  window.activeNameSearch = query;
  input.value = '';
}
function renderEmptyStaffCard() {
  const mount = document.getElementById('cardMount');
  staffPreviewRequest += 1;
  setStaffPreviewMode(false);
  mount.innerHTML = '';
  if (!activeStaffDesign) return;
  CardDesignRuntime.render(mount, activeStaffDesign, {}, {
    recordId: '',
    logoData: activeStaffDesign.logoData || logoData,
    photoLoading: false,
    emptyPreview: true
  });
}
function escapeHtml(value) {
  return String(value == null ? '' : value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}
function renderStaffCard(staff) {
  const mount = document.getElementById('cardMount');
  const requestToken = ++staffPreviewRequest;
  setStaffPreviewMode(false);
  if (!activeStaffDesign) {
    showSetupError('Open Data Sources and select a Staff card design (.json) from your device.');
    return;
  }
  const photoLookupKey = CardDesignRuntime.getPhotoKey(activeStaffDesign, staff);
  const options = {
    recordId: String(staff.recordKey || ''),
    logoData: activeStaffDesign.logoData || logoData,
    photoLoading: Boolean(photoLookupKey)
  };
  CardDesignRuntime.render(mount, activeStaffDesign, staff, options);
  if (!photoLookupKey) return;
  StudioReliability.photo('staff', photoLookupKey).then(function (photo) {
    if (requestToken !== staffPreviewRequest) return;
    options.photoData = photo || '';
    options.photoLoading = false;
    CardDesignRuntime.render(mount, activeStaffDesign, staff, options);
  }).catch(function () {
    if (requestToken !== staffPreviewRequest) return;
    options.photoLoading = false;
    options.photoError = true;
    CardDesignRuntime.render(mount, activeStaffDesign, staff, options);
  });
}
function loadStaffPhotoForPrint(staff) {
  const key = CardDesignRuntime.getPhotoKey(activeStaffDesign, staff);
  return key ? StudioReliability.photo('staff', key).catch(() => '') : Promise.resolve('');
}
function setStaffPreviewMode(showingAll) {
  const mount = document.getElementById('cardMount');
  const selectedPrintButton = document.getElementById('printSelectedStaffButton');
  if (mount) mount.classList.toggle('previewing-all', Boolean(showingAll));
  if (selectedPrintButton) selectedPrintButton.disabled = false;
}
async function previewAllStaffCards(subset) {
  window.activeNameSearch = '';
  const previewRecords = Array.isArray(subset) ? subset : staffRecords;
  if (!Array.isArray(subset)) window.activeNameSearch = '';
  document.getElementById('staffSelect').value = '';
  activeStaffId = '';
  if (!activeStaffDesign) {
    alert('Please select a Staff card design first.');
    return;
  }
  if (!previewRecords.length) {
    alert('There are no staff records to preview.');
    return;
  }
  const requestToken = ++staffPreviewRequest;
  const button = document.getElementById('previewAllStaffButton');
  const mount = document.getElementById('cardMount');
  const status = document.createElement('p');
  const grid = document.createElement('div');
  status.className = 'all-card-preview-status';
  status.textContent = 'Loading photos for 0 of ' + previewRecords.length + ' staff cards…';
  grid.className = 'all-card-preview-grid';
  mount.innerHTML = '';
  setStaffPreviewMode(true);
  mount.append(status, grid);
  const jobs = previewRecords.map(function (staff) {
    const cardMount = document.createElement('div');
    const photoLookupKey = CardDesignRuntime.getPhotoKey(activeStaffDesign, staff);
    const options = {
      recordId: String(staff.recordKey || ''),
      logoData: activeStaffDesign.logoData || logoData,
      photoLoading: Boolean(photoLookupKey)
    };
    grid.appendChild(cardMount);
    CardDesignRuntime.render(cardMount, activeStaffDesign, staff, options);
    return {
      staff: staff,
      mount: cardMount,
      options: options
    };
  });
  let nextJob = 0;
  let completedJobs = 0;
  const workerCount = Math.min(6, jobs.length);
  async function worker() {
    while (nextJob < jobs.length && requestToken === staffPreviewRequest) {
      const job = jobs[nextJob];
      nextJob += 1;
      job.options.photoData = await loadStaffPhotoForPrint(job.staff);
      if (requestToken !== staffPreviewRequest) return;
      job.options.photoLoading = false;
      CardDesignRuntime.render(job.mount, activeStaffDesign, job.staff, job.options);
      completedJobs += 1;
      status.textContent = 'Loading photos for ' + completedJobs + ' of ' + jobs.length + ' staff cards…';
    }
  }
  button.disabled = true;
  try {
    await Promise.all(Array.from({
      length: workerCount
    }, function () {
      return worker();
    }));
    if (requestToken === staffPreviewRequest) {
      status.textContent = 'Showing ' + jobs.length + ' staff ID cards.';
    }
  } finally {
    button.disabled = false;
  }
}
async function printAllStaffCards() {
  if (!activeStaffDesign) {
    alert('Please select a Staff card design first.');
    return;
  }
  if (!staffRecords.length) {
    alert('There are no staff records to print.');
    return;
  }
  const printWindow = CardDesignRuntime.createPrintWindow('Loading photos for ' + staffRecords.length + ' staff cards…');
  if (!printWindow) return;
  const button = document.getElementById('printAllStaffButton');
  const batchContainer = document.createElement('div');
  const jobs = staffRecords.map(function (staff) {
    const mount = document.createElement('div');
    const options = {
      recordId: String(staff.recordKey || ''),
      logoData: activeStaffDesign.logoData || logoData,
      photoLoading: true
    };
    batchContainer.appendChild(mount);
    CardDesignRuntime.render(mount, activeStaffDesign, staff, options);
    return {
      staff: staff,
      mount: mount,
      options: options
    };
  });
  let nextJob = 0;
  let completedJobs = 0;
  const workerCount = Math.min(6, jobs.length);
  async function worker() {
    while (nextJob < jobs.length && !printWindow.closed) {
      const job = jobs[nextJob];
      nextJob += 1;
      job.options.photoData = await loadStaffPhotoForPrint(job.staff);
      job.options.photoLoading = false;
      CardDesignRuntime.render(job.mount, activeStaffDesign, job.staff, job.options);
      completedJobs += 1;
      if (!printWindow.closed) {
        const status = printWindow.document.getElementById('printPreparationStatus');
        if (status) {
          status.textContent = 'Loaded ' + completedJobs + ' of ' + jobs.length + ' staff cards…';
        }
      }
    }
  }
  button.disabled = true;
  try {
    await Promise.all(Array.from({
      length: workerCount
    }, function () {
      return worker();
    }));
    if (!printWindow.closed) {
      CardDesignRuntime.printCards(batchContainer, {
        printWindow: printWindow,
        title: 'All Staff ID Cards'
      });
    }
  } finally {
    button.disabled = false;
  }
}
function openAddStaff() {
  editingStaffId = '';
  document.getElementById('staffModalTitle').textContent = 'Add Staff Member';
  document.getElementById('saveStaffButton').textContent = 'Save';
  document.getElementById('deleteStaffButton').hidden = true;
  document.querySelector('#addStaffModal form').reset();
  renderStaffDesignFields(null);
  document.getElementById('addStaffStatus').textContent = '';
  document.getElementById('addStaffModal').hidden = false;
}
function openEditStaff() {
  const staff = staffRecords.find(function (item) {
    return String(item.recordKey || '') === activeStaffId;
  });
  if (!staff) return alert('Please select a staff member first.');
  editingStaffId = String(staff.recordKey || '');
  document.getElementById('staffModalTitle').textContent = 'Edit Staff';
  document.getElementById('saveStaffButton').textContent = 'Save';
  document.getElementById('deleteStaffButton').hidden = false;
  renderStaffDesignFields(staff);
  document.getElementById('addStaffStatus').textContent = '';
  document.getElementById('addStaffModal').hidden = false;
}
function closeAddStaff() {
  document.getElementById('addStaffModal').hidden = true;
}
function renderStaffDesignFields(staff) {
  const host = document.getElementById('staffDesignLinkedFields');
  host.innerHTML = '';
  const fields = CardDesignRuntime.linkedFormFields(activeStaffDesign, staffSpreadsheetHeaders, staff && Array.isArray(staff._row) ? staff._row : [], [], staffColumnMap);
  if (!fields.length) {
    const message = document.createElement('p');
    message.className = 'status';
    message.style.color = '#b42318';
    message.textContent = 'No data fields are mapped for this design. Open Data Sources → Design Mapping, choose the columns, and save the mapping.';
    host.appendChild(message);
    return;
  }
  fields.forEach(function (field) {
    const wrapper = document.createElement('div');
    const label = document.createElement('label');
    const input = document.createElement('input');
    wrapper.className = 'field';
    label.htmlFor = 'staffLinkedColumn' + field.columnIndex;
    label.textContent = field.label;
    input.id = 'staffLinkedColumn' + field.columnIndex;
    input.className = 'input';
    input.dataset.columnIndex = String(field.columnIndex);
    input.dataset.fieldType = field.type;
    input.value = field.value || '';
    wrapper.appendChild(label);
    wrapper.appendChild(input);
    host.appendChild(wrapper);
  });
}
function collectStaffDesignRecord() {
  return CardDesignRuntime.collectFormValues(document.getElementById('staffDesignLinkedFields'));
}
function deleteCurrentStaff() {
  const staff = staffRecords.find(function (item) {
    return String(item.recordKey || '') === editingStaffId;
  });
  if (!staff) return alert('Please select a staff member first.');
  const fullName = staffMappedFullName(staff);
  if (!confirm('Delete ' + fullName + ' from the spreadsheet and move matching photos to Drive Trash? The app cannot undo this deletion.')) return;
  const button = document.getElementById('deleteStaffButton');
  const status = document.getElementById('addStaffStatus');
  button.disabled = true;
  status.style.color = '#667085';
  status.textContent = 'Deleting staff member and photo...';
  google.script.run.withSuccessHandler(function (result) {
    button.disabled = false;
    closeAddStaff();
    editingStaffId = '';
    populateStaff(result.staff || []);
  }).withFailureHandler(function (error) {
    button.disabled = false;
    status.style.color = '#b42318';
    status.textContent = error.message || String(error);
  }).deleteStaffMember(editingStaffId);
}
function saveNewStaff(event) {
  event.preventDefault();
  const button = document.getElementById('saveStaffButton');
  const status = document.getElementById('addStaffStatus');
  const originalId = editingStaffId;
  const staff = collectStaffDesignRecord();
  if (!Object.keys(staff.columnValues).length) {
    status.style.color = '#b42318';
    status.textContent = 'No data fields are mapped for this design. Open Data Sources → Design Mapping before adding or editing a record.';
    return;
  }
  button.disabled = true;
  status.style.color = '#667085';
  status.textContent = originalId ? 'Updating staff member...' : 'Saving staff member...';
  const call = google.script.run.withSuccessHandler(function (result) {
    button.disabled = false;
    closeAddStaff();
    populateStaff(result.staff || [], result.savedKey);
    editingStaffId = '';
    event.target.reset();
  }).withFailureHandler(function (error) {
    button.disabled = false;
    status.style.color = '#b42318';
    status.textContent = error.message || String(error);
  });
  if (originalId) call.updateStaffMember(staff, originalId);else call.addStaffMember(staff);
}
function openCamera() {
  if (!activeStaffId) return alert('Please select a staff member first.');
  const selectedStaff = staffRecords.find(function (staff) {
    return String(staff.recordKey || '') === activeStaffId;
  });
  if (!selectedStaff) return alert('Please select a staff member first.');
  cameraTargetStaffId = activeStaffId;
  cameraTargetStaffName = staffMappedFullName(selectedStaff);
  if (!cameraTargetStaffName) return alert('This staff member does not have a first and last name.');
  staffCameraWindow = window.open('', 'staffCameraWindow', 'width=760,height=760');
  if (!staffCameraWindow) {
    alert('Please allow pop-ups to open the staff camera.');
    return;
  }
  staffCameraWindow.document.open();
  staffCameraWindow.document.write(\`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Take Staff Photo</title>
<style>
* {
  box-sizing:border-box
}
body {
  min-height:100vh;
  margin:0;
  padding:18px;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:center;
  gap:12px;
  font-family:Arial,sans-serif;
  color:#fff;
  background:#111827
}
select {
  width:100%;
  max-width:560px;
  padding:10px;
  color:#fff;
  background:#202938;
  border:1px solid #4b5563;
  border-radius:7px
}
.frame {
  width:330px;
  height:440px;
  max-width:90vw;
  overflow:hidden;
  background:#000;
  border:2px solid #4b5563;
  border-radius:12px
}
video,img {
  width:100%;
  height:100%;
  object-fit:cover
}
.actions {
  display:flex;
  flex-wrap:wrap;
  justify-content:center;
  gap:9px
}
button {
  min-width:110px;
  padding:10px 14px;
  color:#fff;
  border:0;
  border-radius:7px;
  font-weight:700;
  cursor:pointer
}
button:disabled {
  opacity:.55;
  cursor:not-allowed
}
#capture {
  background:#7141c6
}
#retake {
  background:#e67e22
}
#save {
  background:#1f883d
}
#cancel {
  background:#6b7280
}
#status {
  min-height:18px;
  margin:0;
  color:#fdba74;
  text-align:center;
  font-size:13px
}
</style>
</head>
<body>
<select id="cameraSelect" disabled>
<option value="">Loading cameras...</option>
</select>
<p id="status">Allow camera access when prompted, then choose a camera.</p>
<div class="frame">
<video id="video" autoplay playsinline muted>
</video>
<img id="preview" alt="Captured photo" hidden>
</div>
<div class="actions">
<button id="capture" disabled title="Capture the current camera image for review.">Capture Photo</button>
<button id="retake" hidden title="Discard the captured image and return to the camera.">Retake Photo</button>
<button id="save" disabled title="Save this photo to the connected photo folder for the selected record.">Save Photo</button>
<button id="cancel" title="Close without saving these changes.">Cancel</button>
</div>
<script>
const video = document.getElementById('video');
const preview = document.getElementById('preview');
const select = document.getElementById('cameraSelect');
const capture = document.getElementById('capture');
const retake = document.getElementById('retake');
const save = document.getElementById('save');
const status = document.getElementById('status');
let stream = null;
let photo = '';
function stopStream() {
  if (stream) {
    stream.getTracks().forEach(function (track) {
      track.stop();
    });
    stream = null;
  }
}
async function startCamera(deviceId) {
  stopStream();
  capture.disabled = true;
  status.textContent = 'Starting camera...';
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: deviceId ? {
        deviceId: {
          exact: deviceId
        },
        width: {
          ideal: 1280
        },
        height: {
          ideal: 720
        }
      } : {
        width: {
          ideal: 1280
        },
        height: {
          ideal: 720
        }
      },
      audio: false
    });
    video.srcObject = stream;
    await video.play();
    const cameras = (await navigator.mediaDevices.enumerateDevices()).filter(function (device) {
      return device.kind === 'videoinput';
    });
    const current = stream.getVideoTracks()[0].getSettings().deviceId || deviceId || '';
    select.innerHTML = '';
    cameras.forEach(function (camera, index) {
      const option = document.createElement('option');
      option.value = camera.deviceId;
      option.textContent = camera.label || 'Camera ' + (index + 1);
      select.appendChild(option);
    });
    if (!cameras.length) throw new Error('No camera was found. Connect a camera and reopen this window.');
    select.value = current;
    select.disabled = cameras.length < 2;
    capture.disabled = false;
    status.textContent = '';
  } catch (error) {
    select.innerHTML = '<option>Camera unavailable</option>';
    select.disabled = true;
    status.textContent = 'Camera error: ' + (error.message || error);
  }
}
select.addEventListener('change', function () {
  photo = '';
  startCamera(select.value);
});
capture.addEventListener('click', function () {
  if (!video.videoWidth) return;
  const canvas = document.createElement('canvas');
  canvas.width = 360;
  canvas.height = 480;
  const context = canvas.getContext('2d');
  const sourceAspect = video.videoWidth / video.videoHeight;
  const targetAspect = canvas.width / canvas.height;
  let sw;
  let sh;
  let sx;
  let sy;
  if (sourceAspect > targetAspect) {
    sh = video.videoHeight;
    sw = sh * targetAspect;
    sx = (video.videoWidth - sw) / 2;
    sy = 0;
  } else {
    sw = video.videoWidth;
    sh = sw / targetAspect;
    sx = 0;
    sy = (video.videoHeight - sh) / 2;
  }
  context.drawImage(video, sx, sy, sw, sh, 0, 0, canvas.width, canvas.height);
  photo = canvas.toDataURL('image/jpeg', .9);
  preview.src = photo;
  preview.hidden = false;
  video.hidden = true;
  capture.hidden = true;
  retake.hidden = false;
  save.disabled = false;
});
retake.addEventListener('click', function () {
  photo = '';
  preview.hidden = true;
  video.hidden = false;
  capture.hidden = false;
  retake.hidden = true;
  save.disabled = true;
  status.textContent = '';
});
save.addEventListener('click', function () {
  if (!photo) return;
  save.disabled = true;
  status.textContent = 'Saving photo...';
  window.opener.postMessage({
    sessionToken: window.__STUDIO_TOKEN,
    type: 'STAFF_CAPTURED_PHOTO',
    dataUrl: photo
  }, '*');
});
document.getElementById('cancel').addEventListener('click', function () {
  stopStream();
  window.close();
});
window.addEventListener('message', function (event) {
  if (!event.data || event.data.type !== 'STAFF_PHOTO_RESULT' || event.source !== window.opener) return;
  if (event.data.success) {
    stopStream();
    window.close();
  } else {
    save.disabled = false;
    status.textContent = event.data.error || 'Unable to save photo.';
  }
});
window.addEventListener('beforeunload', stopStream);
if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
  status.textContent = 'This browser does not support camera access.';
} else {
  startCamera('');
}
<\\/script>
</body>
</html>\`);
  staffCameraWindow.document.close();
  StudioReliability.registerPopup(staffCameraWindow);
}
window.addEventListener('message', function (event) {
  if (!event.data || event.data.type !== 'STAFF_CAPTURED_PHOTO') return;
  if (!staffCameraWindow || event.source !== staffCameraWindow) return;
  const popup = event.source;
  const dataUrl = event.data.dataUrl;
  const targetStaffId = cameraTargetStaffId;
  const targetStaffName = cameraTargetStaffName;
  google.script.run.withSuccessHandler(function (result) {
    StudioReliability.invalidate();
    if (!result || !result.success) {
      if (popup && !popup.closed) popup.postMessage({
        type: 'STAFF_PHOTO_RESULT',
        success: false,
        error: result && result.error || 'Unable to save photo.'
      }, '*');
      return;
    }
    if (activeStaffId === targetStaffId) {
      const selectedStaff = staffRecords.find(function (staff) {
        return String(staff.recordKey || '') === targetStaffId;
      });
      if (selectedStaff && activeStaffDesign) {
        CardDesignRuntime.render(document.getElementById('cardMount'), activeStaffDesign, selectedStaff, {
          recordId: targetStaffId,
          logoData: activeStaffDesign.logoData || logoData,
          photoData: dataUrl
        });
      }
      const image = document.getElementById('staffPhoto');
      const placeholder = document.getElementById('staffPhotoPlaceholder');
      const frame = document.getElementById('staffPhotoFrame');
      if (image) {
        image.src = dataUrl;
        image.hidden = false;
      }
      if (placeholder) placeholder.hidden = true;
      if (frame) frame.style.border = 'none';
    }
    if (popup && !popup.closed) popup.postMessage({
      type: 'STAFF_PHOTO_RESULT',
      success: true
    }, '*');
  }).withFailureHandler(function (error) {
    if (popup && !popup.closed) popup.postMessage({
      type: 'STAFF_PHOTO_RESULT',
      success: false,
      error: error.message || String(error)
    }, '*');
  }).saveStaffPhoto(dataUrl, targetStaffId);
});
</script>
<style>
#staffDesignButton {
  white-space: normal;
  overflow-wrap: anywhere;
  height: auto;
  line-height: 1.4;
}
.studio-sync-status {
  margin: 8px 0;
  color: #475467;
  font-size: 12px;
}
</style>
<script>
// Refresh saved sheet values on returning to this studio; never reload the page.
(function () {
  let timer = null;
  let busy = false;
  let lastStarted = 0;
  let hasLeft = false;
  function recordKey(r) {
    return String(r.recordKey || '');
  }
  function status(message, failed) {
    let node = document.getElementById('studioSyncStatus');
    if (!node) {
      node = document.createElement('p');
      node.id = 'studioSyncStatus';
      node.className = 'studio-sync-status';
      node.setAttribute('role', 'status');
      document.getElementById('cardMount').parentNode.prepend(node);
    }
    node.textContent = message;
    node.style.color = failed ? '#b42318' : '#475467';
  }
  function schedule() {
    if (!hasLeft || document.hidden) return;
    clearTimeout(timer);
    timer = setTimeout(refresh, 900);
  }
  function refresh() {
    if (document.hidden || busy || !configuration.hasSpreadsheet) return;
    if (Date.now() - lastStarted < 2000) return;
    // Leave unfinished edits alone; apply fresh records after the dialog closes.
    if (Array.from(document.querySelectorAll('.modal')).some(function (el) {
      return !el.hidden && getComputedStyle(el).display !== 'none';
    })) {
      timer = setTimeout(refresh, 1500);
      return;
    }
    hasLeft = false;
    busy = true;
    lastStarted = Date.now();
    status('Checking for spreadsheet changes…', false);
    google.script.run.withSuccessHandler(function (data) {
      busy = false;
      if (!Array.isArray(data)) {
        status('Could not read spreadsheet updates.', true);
        return;
      }
      if (JSON.stringify(data) === JSON.stringify(staffRecords)) {
        status('Spreadsheet checked. No data changes found.', false);
        return;
      }
      const select = document.getElementById('staffSelect');
      const previous = select.value !== '' ? staffRecords[select.value] : null;
      const showingAll = document.getElementById('cardMount').classList.contains('previewing-all');
      const priorNameSearch = window.activeNameSearch;
      let match = previous ? data.find(function (r) {
        return recordKey(r) === recordKey(previous);
      }) : null;
      if (!match && previous) {
        const sameName = data.filter(function (r) {
          return staffMappedFullName(r) === staffMappedFullName(previous);
        });
        if (sameName.length === 1) match = sameName[0];
      }
      populateStaff(data, match ? recordKey(match) : '');
      if (priorNameSearch) {
        const input = document.getElementById('staffSearchInput');
        input.value = priorNameSearch;
        searchStaffByName();
      } else if (showingAll && data.length) previewAllStaffCards();
      status(previous && !match && !showingAll ? 'Spreadsheet updated. Please select the record again; its identifying details changed or it was removed.' : 'Spreadsheet data reloaded. Any displayed card uses the updated values.', false);
    }).withFailureHandler(function (error) {
      busy = false;
      hasLeft = true;
      status('Unable to update spreadsheet data: ' + (error.message || String(error)) + '. Switch back to this tab to retry.', true);
    }).getStaffData();
  }
  window.addEventListener('blur', function () {
    hasLeft = true;
  });
  window.addEventListener('focus', schedule);
  // Also works when the Apps Script iframe itself does not receive window focus.
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) hasLeft = true;else schedule();
  });
  document.addEventListener('pointerdown', schedule);
})();
</script>
<?!= include('ReliabilityClient'); ?>
</body>
</html>
`;

    case 'Student':
      return `<!DOCTYPE html>
<!-- Student ID Card Studio -->
<html>
<head>
<script>
window.STUDIO_URL = <?!= JSON.stringify(webAppUrl) ?>;
window.STUDIO_TYPE = <?!= JSON.stringify(studioType) ?>;
window.STUDIO_SCOPE = <?!= JSON.stringify(clientScope) ?>;
window.STUDIO_STORAGE = {
  getItem: function (k) {
    return localStorage.getItem(STUDIO_SCOPE + k);
  },
  setItem: function (k, v) {
    localStorage.setItem(STUDIO_SCOPE + k, v);
  },
  removeItem: function (k) {
    localStorage.removeItem(STUDIO_SCOPE + k);
  }
};
</script>
<base target="_top">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="https://cdn.jsdelivr.net/npm/jsbarcode@3.11.5/dist/JsBarcode.all.min.js"></script>
<style>
:root {
  --primary: #185adb;
  --primary-dark: #1248b5;
  --ink: #172033;
  --muted: #667085;
  --line: #dce3ec;
  --panel: rgba(255, 255, 255, 0.96);
  --canvas: #e9eef5;
}
* {
  box-sizing: border-box;
}
[hidden] {
  display: none !important;
}
body {
  font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
  color: var(--ink);
  background-color: #f3f6fa;
  background-image: linear-gradient(135deg, #f7f9fc 0%, #e9eff7 100%);
  min-height: 100vh;
  margin: 0;
  padding: 24px;
}
.setup-screen {
  width: 100%;
  min-height: calc(100vh - 48px);
  display: grid;
  place-items: center;
}
.setup-card {
  width: 100%;
  max-width: 560px;
  padding: 30px;
  background: rgba(255, 255, 255, .97);
  border: 1px solid var(--line);
  border-radius: 18px;
  box-shadow: 0 20px 50px rgba(33, 48, 73, .13);
}
.setup-icon {
  width: 50px;
  height: 50px;
  margin-bottom: 16px;
  display: grid;
  place-items: center;
  color: #fff;
  background: linear-gradient(135deg, var(--primary), #6f42c1);
  border-radius: 14px;
  font-size: 16px;
  font-weight: 800;
}
.setup-icon svg, .brand-badge svg {
  width: 34px;
  height: 34px;
  display: block;
  filter: drop-shadow(0 2px 3px rgba(23,32,51,.24));
}
.setup-card h1 {
  margin: 0;
  font-size: 25px;
}
.setup-intro {
  margin: 7px 0 22px;
  color: var(--muted);
  font-size: 14px;
  line-height: 1.5;
}
.setup-fields {
  display: flex;
  flex-direction: column;
  gap: 15px;
}
.setup-note {
  margin: 6px 0 0;
  color: var(--muted);
  font-size: 11px;
}
.setup-submit {
  margin-top: 20px;
}
.setup-status {
  min-height: 20px;
  margin: 10px 0 0;
  color: #b42318;
  font-size: 13px;
  font-weight: 600;
}
.setup-back-link {
  display: inline-block;
  margin-top: 12px;
  color: var(--primary);
  font-size: 13px;
  font-weight: 700;
  text-decoration: none;
}
.setup-back-link:hover {
  text-decoration: underline;
}
.app-header {
  width: 100%;
  max-width: none;
  margin: 0 auto 18px;
  padding: 0 2px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
}
.brand-group {
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 12px;
}
.brand-badge {
  width: 44px;
  height: 44px;
  flex: 0 0 44px;
  display: grid;
  place-items: center;
  color: #fff;
  background: linear-gradient(135deg, var(--primary), #6f42c1);
  border-radius: 12px;
  box-shadow: 0 8px 18px rgba(24, 90, 219, .22);
  font-size: 15px;
  font-weight: 800;
  letter-spacing: .5px;
}
.app-header h1 {
  margin: 0;
  font-size: 22px;
  line-height: 1.15;
}
.app-header p {
  margin: 3px 0 0;
  color: var(--muted);
  font-size: 13px;
}
.format-pill {
  padding: 7px 11px;
  flex: 0 0 auto;
  color: #344054;
  background: rgba(255, 255, 255, .82);
  border: 1px solid var(--line);
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
}
.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
.edit-setup-btn {
  padding: 7px 11px;
  color: #344054;
  background: rgba(255, 255, 255, .9);
  border: 1px solid var(--line);
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
  text-decoration: none;
}
.edit-setup-btn:hover {
  color: var(--primary);
  border-color: #a8bde9;
}
.edit-setup-btn.id-studio-link {
  display: inline-flex;
  align-items: center;
  color: #ffffff;
  background: #17233a;
  border-color: #17233a;
  border-radius: 9px;
}
.edit-setup-btn.id-studio-link:hover {
  color: #ffffff;
  background: #101a2c;
  border-color: #101a2c;
}
.source-note {
  margin: 6px 0 0;
  color: var(--muted);
  font-size: 11px;
  line-height: 1.4;
}
.source-status {
  min-height: 18px;
  margin: 9px 0 0;
  color: #b42318;
  font-size: 12px;
  font-weight: 700;
}
.main-layout-container {
  width: 100%;
  max-width: none;
  margin: 0 auto;
  display: flex;
  flex-direction: row;
  min-height: calc(100vh - 110px);
  align-items: flex-start;
  gap: 18px;
}
.controls-container {
  display: flex;
  flex: 0 0 350px;
  min-width: 350px;
  flex-direction: column;
  align-items: stretch;
  gap: 0;
  overflow: hidden;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 14px;
  box-shadow: 0 10px 30px rgba(33, 48, 73, .08);
}
.control-section {
  padding: 15px 16px;
  border-bottom: 1px solid #edf0f4;
}
.control-section:last-child {
  border-bottom: 0;
}
.data-sources-panel {
  order: 99;
  border-top: 1px solid #edf0f4;
  border-bottom: 0;
}
.data-sources-panel > summary {
  margin: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  list-style: none;
  cursor: pointer;
  user-select: none;
}
.data-sources-panel > summary::-webkit-details-marker {
  display: none;
}
.data-sources-panel > summary::after {
  content: '+';
  width: 23px;
  height: 23px;
  display: grid;
  place-items: center;
  flex: 0 0 23px;
  color: var(--primary);
  background: #edf4ff;
  border-radius: 6px;
  font-size: 17px;
  line-height: 1;
}
.data-sources-panel[open] > summary {
  margin-bottom: 11px;
}
.data-sources-panel[open] > summary::after {
  content: '−';
}
.source-sheet-button {
  background: #185adb !important;
}
.source-sheet-button:hover {
  background: #1248b5 !important;
}
.source-folder-button {
  background: #0f8b8d !important;
}
.source-folder-button:hover {
  background: #0b7173 !important;
}
.source-design-button {
  background: #7141c6 !important;
}
.source-design-button:hover {
  background: #58309f !important;
}
.section-title {
  margin: 0 0 11px;
  color: #475467;
  font-size: 11px;
  font-weight: 800;
  letter-spacing: .08em;
  text-transform: uppercase;
}
.section-stack {
  display: flex;
  flex-direction: column;
  gap: 9px;
}
.field-label {
  display: block;
  margin-bottom: 5px;
  color: #344054;
  font-size: 12px;
  font-weight: 700;
}
.button-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 9px;
}
.button-grid .btn-action:last-child:nth-child(odd) {
  grid-column: 1 / -1;
}
.preview-panel {
  min-width: 0;
  min-height: calc(100vh - 110px);
  flex: 1 1 auto;
  overflow: hidden;
  background: rgba(255, 255, 255, .76);
  border: 1px solid var(--line);
  border-radius: 14px;
  box-shadow: 0 10px 30px rgba(33, 48, 73, .08);
}
.preview-toolbar {
  min-height: 64px;
  padding: 12px 18px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  background: rgba(255, 255, 255, .92);
  border-bottom: 1px solid var(--line);
}
.preview-toolbar h2 {
  margin: 0;
  font-size: 16px;
}
.preview-toolbar p {
  margin: 3px 0 0;
  color: var(--muted);
  font-size: 12px;
}
.preview-canvas {
  min-height: calc(100vh - 174px);
  padding: 34px;
  overflow: auto;
  background-color: var(--canvas);
  background-image: linear-gradient(45deg, rgba(255,255,255,.45) 25%, transparent 25%), linear-gradient(-45deg, rgba(255,255,255,.45) 25%, transparent 25%), linear-gradient(45deg, transparent 75%, rgba(255,255,255,.45) 75%), linear-gradient(-45deg, transparent 75%, rgba(255,255,255,.45) 75%);
  background-size: 20px 20px;
  background-position: 0 0, 0 10px, 10px -10px, -10px 0;
}
.url-container {
  position: relative;
  z-index: 10;
}
.url-container label {
  display: block;
  margin-bottom: 5px;
  color: #344054;
  font-size: 12px;
  font-weight: 700;
}
.url-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.url-row input {
  min-width: 0;
  flex: 1;
}
.search-wrapper {
  position: relative;
  width: 100%;
  display: flex;
  align-items: center;
}
.search-input, .select-input, .text-input, .url-input {
  width: 100%;
  min-height: 38px;
  padding: 8px 11px;
  font-size: 13px;
  border: 1px solid #d0d7de;
  border-radius: 8px;
  background-color: #fff;
  outline: none;
  box-sizing: border-box;
}
.search-input {
  padding-right: 32px;
}
.search-input:focus, .select-input:focus, .text-input:focus, .url-input:focus {
  border-color: #0969da;
  box-shadow: 0 0 0 2px rgba(9, 105, 218, 0.2);
}
.select-input {
  cursor: pointer;
}
.search-btn {
  position: absolute;
  right: 4px;
  padding: 4px 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #57606a;
  background: none;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}
.search-btn:hover {
  color: #0969da;
  background-color: #f3f4f6;
}
.btn-action {
  width: 100%;
  min-height: 38px;
  padding: 8px 12px;
  color: #fff;
  background-color: #0969da;
  font-size: 13px;
  font-weight: 600;
  border: none;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, .08);
  cursor: pointer;
  transition: background-color 0.2s;
}
.url-row .btn-action {
  width: auto;
  flex: 0 0 auto;
}
.btn-action:hover {
  background-color: #0451a5;
}
.btn-action:disabled {
  opacity: 0.6;
  cursor: wait;
}
.btn-print {
  background-color: #1f883d;
}
.btn-print:hover {
  background-color: #1a7333;
}
#bg-logo-btn {
  background-color: #ff8c00;
}
#bg-logo-btn:hover {
  background-color: #e07b00;
}
#add-student-btn {
  background-color: #6f42c1;
}
#add-student-btn:hover {
  background-color: #59339d;
}
input[type="file"] {
  display: none;
}
#cardsWrapper {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 16px;
  align-items: flex-start;
}
#cardsWrapper.previewing-all {
  width: 100%;
}
.all-card-preview-grid {
  width: 100%;
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  align-items: flex-start;
  gap: 24px;
}
.all-card-preview-status {
  width: 100%;
  margin: 0 0 18px;
  color: #475467;
  font-size: 12px;
  font-weight: 750;
  text-align: center;
}
.cr80-card-portrait {
  width: 204px;
  height: 324px;
  padding: 8px;
  display: flex;
  flex-direction: column;
  align-items: center;
  position: relative;
  overflow: hidden;
  box-sizing: border-box;
  background: #fff;
  border: 1px solid #d0d7de;
  border-radius: 12px;
  box-shadow: 0 8px 20px rgba(0, 0, 0, 0.12);
}
.top-header {
  width: 100%;
  height: 70px;
  padding: 18px 0 0;
  display: flex;
  align-items: flex-end;
  justify-content: center;
  position: relative;
  flex: 0 0 70px;
  box-sizing: border-box;
  border-bottom: 1px solid #e1e4e8;
  overflow: hidden;
}
/*
     * Keeps the uploaded logo away from a physical, top-center lanyard slot.
     * The outline is only an alignment guide in the on-screen preview.
     */
.lanyard-hole-safe-area {
  width: 56px;
  height: 12px;
  position: absolute;
  top: 2px;
  left: 50%;
  transform: translateX(-50%);
  box-sizing: border-box;
  border: 1px dashed #a8b0b8;
  border-radius: 8px;
  pointer-events: none;
}
.logo-img {
  display: block;
  width: 100%;
  height: 100%;
  max-width: 188px;
  max-height: 52px;
  object-fit: contain;
  object-position: center center;
  margin: 0 auto;
}
.photo-section {
  position: relative;
  width: 100%;
  height: 126px;
  margin: 1px 0;
  display: flex;
  flex: 0 0 126px;
  align-items: center;
  justify-content: center;
  box-sizing: border-box;
}
.photo-frame {
  width: 104px;
  height: 122px;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  background-color: #f6f8fa;
  border: 1px dashed #0969da;
  border-radius: 6px;
}
.photo-frame span {
  font-size: 9px;
  color: #57606a;
  font-weight: 600;
}
.photo-img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}
.year-container {
  position: absolute;
  left: -25px;
  top: 50%;
  transform: translateY(-50%) rotate(-90deg);
  display: flex;
  align-items: center;
  justify-content: center;
  white-space: nowrap;
  font-size: 13px;
  font-weight: bold;
  color: #f00;
  letter-spacing: 1px;
}
.grade-container {
  position: absolute;
  right: 11px;
  top: 50%;
  height: 122px;
  transform: translateY(-50%) rotate(180deg);
  display: flex;
  flex-direction: row;
  align-items: center;
  justify-content: center;
  writing-mode: vertical-rl;
  gap: 4px;
}
.grade-label {
  font-size: 13px;
  font-weight: bold;
  color: #00f;
  letter-spacing: 1px;
  text-transform: uppercase;
}
.grade-value {
  font-size: 13px;
  font-weight: 800;
  color: #000;
}
.card-body {
  width: 100%;
  flex-grow: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-start;
  gap: 0;
  overflow: hidden;
  text-align: center;
  color: #24292f;
}
.name-block {
  width: 100%;
  margin-bottom: 2px;
  flex: 0 0 auto;
}
.person-first-name, .person-last-name {
  max-width: 100%;
  overflow: hidden;
  font-size: 15px;
  font-weight: bold;
  color: #000;
  line-height: 1;
  white-space: nowrap;
  text-overflow: ellipsis;
  text-transform: uppercase;
}
.person-last-name {
  margin-top: 0;
}
.bus-container, .walk-container {
  height: 25px;
  margin: 0 !important;
  line-height: 0;
  flex: 0 0 25px;
}
.bus-container svg, .walk-container svg {
  width: 24px;
  height: 24px;
}
.person-id {
  margin-bottom: 0;
  font-size: 12px;
  line-height: 1;
  font-weight: 600;
  color: #000;
}
.barcode-container {
  width: 100%;
  margin-top: 0;
  display: flex;
  flex: 0 0 auto;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}
.barcode-svg {
  max-width: 180px;
  height: 32px;
}
.missing-photo-modal {
  position: fixed;
  inset: 0;
  z-index: 3000;
  padding: 24px;
  display: grid;
  place-items: center;
  background: rgba(15, 23, 42, .68);
}
.missing-photo-dialog {
  width: min(820px, 100%);
  max-height: calc(100vh - 48px);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background: #fff;
  border-radius: 16px;
  box-shadow: 0 24px 70px rgba(15, 23, 42, .32);
}
.missing-photo-head {
  padding: 18px 20px;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
  border-bottom: 1px solid var(--line);
}
.missing-photo-head h2 {
  margin: 0;
  font-size: 19px;
}
.missing-photo-head p {
  margin: 5px 0 0;
  color: var(--muted);
  font-size: 12px;
}
.missing-photo-close {
  width: auto;
  min-width: 76px;
  background: #667085;
}
.missing-photo-close:hover {
  background: #4f5968;
}
.missing-photo-summary {
  min-height: 43px;
  padding: 12px 20px;
  color: #344054;
  background: #f8fafc;
  border-bottom: 1px solid #e8edf3;
  font-size: 13px;
  font-weight: 750;
}
.missing-photo-table-wrap {
  overflow: auto;
}
.missing-photo-table {
  width: 100%;
  border-collapse: collapse;
}
.missing-photo-table th, .missing-photo-table td {
  padding: 10px 12px;
  border-bottom: 1px solid #edf0f4;
  font-size: 12px;
  text-align: left;
}
.missing-photo-table th {
  position: sticky;
  top: 0;
  z-index: 1;
  color: #344054;
  background: #f2f5f9;
  font-size: 10px;
  letter-spacing: .06em;
  text-transform: uppercase;
}
.missing-photo-table tbody tr:nth-child(even) {
  background: #fafbfd;
}
.missing-photo-empty {
  padding: 34px 18px !important;
  color: #1f883d;
  font-weight: 800;
  text-align: center !important;
}
.missing-photo-actions {
  padding: 14px 20px;
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 9px;
  border-top: 1px solid var(--line);
  background: #fff;
}
.missing-photo-refresh {
  background: #185adb;
}
.missing-photo-print {
  background: #7141c6;
}
.missing-photo-download {
  background: #1f883d;
}
.missing-photo-list-button {
  background: #b42318 !important;
}
.missing-photo-list-button:hover {
  background: #8f1c14 !important;
}
@media (max-width: 650px) {
  body {
    padding: 14px;
  }
  .app-header {
    align-items: flex-start;
  }
  .format-pill {
    display: none;
  }
  .main-layout-container {
    min-height: 0;
    flex-direction: column;
  }
  .controls-container {
    width: 100%;
    min-width: 0;
    flex-basis: auto;
  }
  .preview-panel {
    width: 100%;
    min-height: 480px;
  }
  .preview-canvas {
    min-height: 415px;
    padding: 24px 12px;
  }
  .missing-photo-modal {
    padding: 10px;
  }
  .missing-photo-dialog {
    max-height: calc(100vh - 20px);
  }
  .missing-photo-actions {
    grid-template-columns: 1fr 1fr;
  }
}
@media print {
  @page {
    size: auto;
    margin: 0;
  }
  body {
    display: block !important;
    padding: 0 !important;
    margin: 0 !important;
    background: transparent !important;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
  }
  .app-header, .setup-screen, .controls-container, .preview-toolbar, .missing-photo-modal, .all-card-preview-status {
    display: none !important;
  }
  .main-layout-container, .preview-panel, .preview-canvas {
    width: auto !important;
    min-height: 0 !important;
    padding: 0 !important;
    margin: 0 !important;
    overflow: visible !important;
    background: transparent !important;
    border: 0 !important;
    border-radius: 0 !important;
    box-shadow: none !important;
  }
  #cardsWrapper {
    display: block !important;
  }
  .cr80-card-portrait {
    width: 53.98mm !important;
    height: 85.60mm !important;
    margin: 0 !important;
    padding: 0.083in !important;
    border: none !important;
    border-radius: 0 !important;
    box-shadow: none !important;
    page-break-after: always;
    break-after: page;
  }
  /* The physical slot is already present, so do not print the guide. */
  .lanyard-hole-safe-area {
    border-color: transparent !important;
  }
}
</style>
<style>@media print {.student-print-list-add,#studentPrintListPanel {display:none!important}}</style>
</head>
<body>
<header class="app-header" id="appHeader">
<div class="brand-group">
<div class="brand-badge" role="img" aria-label="Student">
<svg viewBox="0 0 48 48" aria-hidden="true">
<path d="M12 41c1-8 5.5-12 12-12s11 4 12 12" fill="#38d0b4"/>
<circle cx="24" cy="23" r="7" fill="#ffbf91"/>
<path d="M7 15L24 7l17 8-17 8-17-8z" fill="#ffd34e"/>
<path d="M14 19v5c5.5 4.8 14.5 4.8 20 0v-5" fill="#6f56d9"/>
<path d="M40 16v9" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/>
<circle cx="40" cy="27" r="2" fill="#ff7a59"/>
</svg>
</div>
<div>
<h1>Student ID Card Studio</h1>
<p>Find students, manage their records and photos, and print cards using your selected design.</p>
</div>
</div>
<div class="header-actions">
<a class="edit-setup-btn id-studio-link" href="<?!= webAppUrl ?>" target="_top">← ID Card Studio</a>
</div>
</header>
<main class="main-layout-container" id="appMain">
<aside class="controls-container" aria-label="ID card controls">
<details id="studentDataSources" class="control-section studio-configuration data-sources-panel">
<summary class="section-title">Data Sources</summary>
<p class="source-note">Connect a spreadsheet to open Design Mapping. Choose a design, worksheet, header option, and columns together. Internal record and photo columns are reused when you change designs.</p>
<div class="section-stack">
<div class="url-container">
<label for="spreadsheetUrl">Student Spreadsheet</label>
<div class="url-row">
<input type="url" id="spreadsheetUrl" class="url-input" placeholder="Paste spreadsheet URL">
<button type="button" class="btn-action source-sheet-button" id="acceptSpreadsheetUrlBtn" onclick="acceptSpreadsheetUrl()">Connect</button>
</div>
<p id="spreadsheetSourceNote" class="source-note">Connect the Google spreadsheet used for student records. Saved connections are remembered for your Google account.</p>
</div>
<div class="url-container">
<label for="photoFolderUrl">Student Photo Folder</label>
<div class="url-row">
<input type="url" id="photoFolderUrl" class="url-input" placeholder="Paste Drive folder URL">
<button type="button" class="btn-action source-folder-button" id="acceptPhotoFolderUrlBtn" onclick="acceptPhotoFolderUrl()">Connect</button>
</div>
<p id="photoFolderSourceNote" class="source-note">Connect the folder for student photos. Photo filenames must match the Student ID Number, for example 12345.jpg.</p>
</div>
<div>
<label class="field-label">Student Card Design</label>
<input type="file" id="setupDesignFile" accept=".json,application/json" onchange="selectStudentCardDesign(event)">
<button type="button" id="setupDesignButton" class="btn-action source-design-button" onclick="openStudentColumnMapping()" title="Choose a saved Design Studio .json file from your device.">Select Card Design</button>
<p id="setupDesignNote" class="source-note">Choose a .json design file saved in Design Studio, then map its data elements below.</p>
</div>
<div>
<label class="field-label">Design Mapping</label>
<button type="button" id="studentMappingButton" class="btn-action" style="background:#d97706" onclick="openStudentColumnMapping()" title="Choose which spreadsheet column supplies each data element in this design.">Design Mapping</button>
<p id="studentMappingNote" class="source-note">Connect a spreadsheet, select a design, then match its data elements to spreadsheet columns.</p>
</div>
</div>
<p id="setupStatus" class="source-status" role="status">
</p>
</details>
<section class="control-section">
<h2 class="section-title">Find Students</h2>
<div class="section-stack">
<div class="search-wrapper">
<input type="search" id="studentNameSearchInput" class="search-input" placeholder="Search by Student Full Name" autocomplete="off" onkeydown="if (event.key === 'Enter') { event.preventDefault(); searchStudentByFullName(); }">
<button type="button" class="search-btn" onclick="searchStudentByFullName()" title="Search by Student Full Name" aria-label="Search by student full name">
<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
<circle cx="11" cy="11" r="8">
</circle>
<line x1="21" y1="21" x2="16.65" y2="16.65">
</line>
</svg>
</button>
</div>
<div class="search-wrapper">
<input type="text" id="idSearchInput" class="search-input" placeholder="Search by Student ID Number" onkeydown="if (event.key === 'Enter') searchStudentById()">
<button type="button" class="search-btn" onclick="searchStudentById()" title="Search by Student ID Number" aria-label="Search by student ID number">
<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
<circle cx="11" cy="11" r="8">
</circle>
<line x1="21" y1="21" x2="16.65" y2="16.65">
</line>
</svg>
</button>
</div>
<div class="search-wrapper">
<input type="text" id="gradeSearchInput" class="search-input" placeholder="Search by Student Grade Level" onkeydown="if (event.key === 'Enter') searchStudentByGrade()">
<button type="button" class="search-btn" onclick="searchStudentByGrade()" title="Search by Student Grade Level" aria-label="Search by student grade level">
<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
<circle cx="11" cy="11" r="8">
</circle>
<line x1="21" y1="21" x2="16.65" y2="16.65">
</line>
</svg>
</button>
</div>
<select id="recordSelect" class="select-input" onchange="handleRecordSelect(this)">
<option value="" selected>Select Student</option>
</select>
</div>
</section>
<section class="control-section">
<h2 class="section-title">Actions</h2>
<div class="button-grid">
<button type="button" class="btn-action" id="add-student-btn" style="background:#1f883d" onclick="openAddStudentPopup()" title="Add a student using the fields mapped in your selected design.">Add Student</button>
<button type="button" class="btn-action" style="background:#7141c6" onclick="openEditStudentPopup()" title="Change or delete the selected student record.">Edit Student</button>
<button type="button" class="btn-action" id="takePictureBtn" style="background:#d97706" onclick="openCamera()" title="Open the camera for the selected record. Capture, review, and save a photo.">Take Photo</button>
</div>
</section>
<section class="control-section">
<h2 class="section-title">Data</h2>
<div class="button-grid">
<button type="button" class="btn-action" style="background:#185adb" onclick="openSavedResource('spreadsheet')" title="Open the connected spreadsheet in a new tab. Return here to reload saved changes.">Open the Spreadsheet</button>
<button type="button" class="btn-action" style="background:#0f8b8d" onclick="openSavedResource('folder')" title="Open the connected Google Drive photo folder in a new tab.">Open the Photo Folder</button>
<button type="button" class="btn-action missing-photo-list-button" onclick="openMissingPhotoList()" title="List students without a matching photo filename in the connected folder.">Missing Photo List</button>
</div>
</section>
</aside>
<section class="preview-panel" aria-label="Card preview">
<div class="preview-toolbar">
<div>
<h2>Student ID Card Preview</h2>
<p>Select a student or search by grade to display cards. Preview All displays every student; Print All prepares every student card. Choose the side in print preview.</p>
</div>
<div style="display:flex;align-items:center;justify-content:flex-end;gap:10px;flex-wrap:wrap">
<button id="previewAllStudentsButton" type="button" class="btn-action" style="width:auto;background:#7141c6" onclick="previewAllStudentCards()" title="Display all records using the selected design. This does not print.">Preview All Student ID Cards</button>
<button id="printSelectedStudentButton" type="button" class="btn-action btn-print" style="width:auto;background:#b42318" onclick="CardDesignRuntime.printCards(document.getElementById('cardsWrapper'),{title:'Student ID Card Print Preview'})" title="Print the currently displayed student or grade group. Choose the card side in print preview.">Print Displayed Student ID Cards</button>
<button id="printAllStudentsButton" type="button" class="btn-action btn-print" style="width:auto;background:#185adb" onclick="printAllStudentCards()" title="Prepare all records for printing, then choose the card side in print preview.">Print All Student ID Cards</button>
<button id="openStudentPrintListButton" type="button" class="btn-action" style="width:auto;background:#475467" onclick="openStudentPrintList()" aria-haspopup="dialog" aria-controls="studentPrintListPanel">Print List (0)</button>
</div>
</div>
<div class="preview-canvas">

<div id="cardsWrapper">
</div>
</div>
</section>
</main>
<dialog id="studentPrintListPanel" aria-labelledby="studentPrintListSummary" style="width:min(600px,calc(100vw - 32px));max-height:85vh;overflow:auto;padding:22px;border:1px solid #dce3ec;border-radius:12px;background:#f8fafc;color:#172033;box-shadow:0 20px 60px #17203344">
  <h2 id="studentPrintListSummary" style="margin:0 0 12px;font-size:20px">Print List (0)</h2>
  <p style="font-size:12px;color:#667085">Add students from any search. This list lasts until you reload or leave the studio. Cards use the currently selected design.</p>
  <div id="studentPrintListRows" style="max-height:240px;overflow:auto"></div>
  <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
    <button id="printStudentListButton" class="btn-action btn-print" style="width:auto" type="button" disabled onclick="printStudentList()">▣ Print Listed Cards</button>
    <button id="clearStudentListButton" class="btn-action" style="width:auto;background:#475467" type="button" disabled onclick="clearStudentPrintList()">⌫ Clear List</button>
    <button type="button" class="btn-action" style="width:auto;background:#475467" onclick="document.getElementById('studentPrintListPanel').close()">Close</button>
  </div>
  <p id="studentPrintListStatus" role="status" aria-live="polite" style="font-size:12px;color:#475467"></p>
</dialog>
<div id="missingPhotoModal" class="missing-photo-modal" role="dialog" aria-modal="true" aria-labelledby="missingPhotoTitle" onclick="if(event.target===this) closeMissingPhotoList()" hidden>
<div class="missing-photo-dialog">
<div class="missing-photo-head">
<div>
<h2 id="missingPhotoTitle">Students Missing Photos</h2>
<p>Compare student ID numbers with filenames in the connected photo folder. This checks for matching files; it does not verify image quality.</p>
</div>
</div>
<div id="missingPhotoSummary" class="missing-photo-summary" role="status">Checking spreadsheet records and photo files…</div>
<div class="missing-photo-table-wrap">
<table class="missing-photo-table">
<thead>
<tr>
<th>Student ID</th>
<th>First Name</th>
<th>Last Name</th>
<th>Grade Level</th>
</tr>
</thead>
<tbody id="missingPhotoTableBody">
<tr>
<td colspan="4">Loading…</td>
</tr>
</tbody>
</table>
</div>
<div class="missing-photo-actions">
<button id="refreshMissingPhotosButton" type="button" class="btn-action missing-photo-refresh" onclick="loadMissingPhotoList()" title="Check the spreadsheet and photo folder again.">Refresh</button>
<button type="button" class="btn-action missing-photo-print" onclick="printMissingPhotoList()" title="Print the missing-photo report.">Print List</button>
<button type="button" class="btn-action missing-photo-download" onclick="downloadMissingPhotoCsv()" title="Download the missing-photo report as a CSV file.">Download CSV</button>
<button type="button" class="btn-action missing-photo-close" onclick="closeMissingPhotoList()">Close</button>
</div>
</div>
</div>
<?!= include('DesignRuntime'); ?>
<script>
const LOGO_KEY = 'cr80_project_logo_portrait';
const ACTIVE_DESIGN_KEY = 'active_student_card_design';
let recordsList = [];
const studentPrintList = new Set();
let studentPrintListScope = window.STUDIO_SCOPE;
let studentListPrinting = false;
function syncStudentPrintList() {
  if (studentPrintListScope !== window.STUDIO_SCOPE) {
    studentPrintList.clear();
    studentPrintListScope = window.STUDIO_SCOPE;
  }
  const current = new Set(recordsList.map(record => String(record.recordKey || '')));
  studentPrintList.forEach(key => { if (!current.has(key)) studentPrintList.delete(key); });
  const summary = document.getElementById('studentPrintListSummary');
  if (!summary) return;
  summary.textContent = 'Print List (' + studentPrintList.size + ')';
  const opener = document.getElementById('openStudentPrintListButton');
  if (opener) opener.textContent = summary.textContent;
  const rows = document.getElementById('studentPrintListRows');
  rows.replaceChildren();
  if (!studentPrintList.size) rows.textContent = 'No students added yet.';
  studentPrintList.forEach(key => {
    const person = recordsList.find(record => String(record.recordKey || '') === key);
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:12px;padding:8px 0;border-bottom:1px solid #dce3ec';
    const label = document.createElement('span');
    const id = studentMappedValue(person, 'idNumber', person.idNumber || '');
    label.textContent = (studentMappedFullName(person) || 'Student') + (id ? ' (' + id + ')' : '');
    const remove = document.createElement('button');
    remove.type = 'button'; remove.textContent = 'Remove';
    remove.style.cssText = 'padding:7px 12px;border:1px solid #d0d5dd;border-radius:6px;background:#fff;color:#b42318;cursor:pointer';
    remove.disabled = studentListPrinting;
    remove.onclick = () => { studentPrintList.delete(key); syncStudentPrintList(); };
    row.append(label, remove); rows.appendChild(row);
  });
  document.getElementById('printStudentListButton').disabled = studentListPrinting || !studentPrintList.size;
  document.getElementById('clearStudentListButton').disabled = studentListPrinting || !studentPrintList.size;
  document.querySelectorAll('[data-student-print-key]').forEach(button => {
    const added = studentPrintList.has(button.dataset.studentPrintKey);
    button.textContent = added ? '✓ In Print List' : '＋ Add to Print List';
    button.disabled = added || studentListPrinting;
  });
}
function studentPrintListCard(person, mount, container) {
  const group = document.createElement('div');
  group.style.cssText = 'display:flex;flex-direction:column;align-items:flex-start;gap:8px';
  const button = document.createElement('button');
  const key = String(person.recordKey || '');
  button.type = 'button'; button.className = 'btn-action student-print-list-add';
  button.style.cssText = 'width:auto;min-height:38px';
  button.dataset.studentPrintKey = key;
  button.textContent = studentPrintList.has(key) ? '✓ In Print List' : '＋ Add to Print List';
  button.disabled = !key || studentPrintList.has(key) || studentListPrinting;
  button.onclick = () => {
    syncStudentPrintList();
    if (!recordsList.some(record => String(record.recordKey || '') === key)) return;
    studentPrintList.add(key); syncStudentPrintList();
    document.getElementById('studentPrintListStatus').textContent = 'Added ' + (studentMappedFullName(person) || 'student') + '. Search for another student or open the Print List.';
  };
  group.append(button, mount); container.appendChild(group);
}
function openStudentPrintList() {
  syncStudentPrintList();
  const dialog = document.getElementById('studentPrintListPanel');
  if (!dialog.open) dialog.showModal();
}
function clearStudentPrintList() {
  if (studentListPrinting || !studentPrintList.size || !confirm('Remove all students from this print list?')) return;
  studentPrintList.clear(); syncStudentPrintList();
  document.getElementById('studentPrintListStatus').textContent = 'Print list cleared.';
}
async function printStudentList() {
  if (studentListPrinting) return;
  syncStudentPrintList();
  const selected = Array.from(studentPrintList).map(key => recordsList.find(record => String(record.recordKey || '') === key)).filter(Boolean);
  if (!selected.length) return;
  studentListPrinting = true; syncStudentPrintList();
  try { await printStudentBatch(selected, 'printStudentListButton'); }
  finally { studentListPrinting = false; syncStudentPrintList(); }
}

let spreadsheetHeaders = [];
let savedLogoData = '';
let activeStudentId = '';
let addStudentWindow = null;
let activeCardDesign = null;
let studentColumnMap = {};
const studentPhotoCache = Object.create(null);
const STUDENT_PHOTO_DATABASE = STUDIO_SCOPE + 'student-photo-cache';
const STUDENT_PHOTO_STORE = 'photos';
let studentPhotoDatabasePromise = null;
let missingPhotoReport = [];
let missingPhotoStudentTotal = 0;
let studentPreviewRequest = 0;
let initialConfiguration = {
  hasSpreadsheet: false,
  hasPhotoFolder: false
};

/*
 * Keep optimized Drive thumbnails on this device. A cache key contains the
 * Drive file ID and last-modified time, so replacing a photo automatically
 * causes the new image to be downloaded.
 */
function openStudentPhotoDatabase() {
  if (!window.indexedDB) return Promise.resolve(null);
  if (studentPhotoDatabasePromise) return studentPhotoDatabasePromise;
  studentPhotoDatabasePromise = new Promise(function (resolve) {
    const request = window.indexedDB.open(STUDENT_PHOTO_DATABASE, 1);
    request.onupgradeneeded = function () {
      const database = request.result;
      if (!database.objectStoreNames.contains(STUDENT_PHOTO_STORE)) {
        database.createObjectStore(STUDENT_PHOTO_STORE);
      }
    };
    request.onsuccess = function () {
      const database = request.result;
      database.onversionchange = function () {
        database.close();
      };
      resolve(database);
    };
    request.onerror = function () {
      resolve(null);
    };
    request.onblocked = function () {
      resolve(null);
    };
  });
  return studentPhotoDatabasePromise;
}
function readStoredStudentPhoto(storageKey) {
  if (!storageKey) return Promise.resolve('');
  return openStudentPhotoDatabase().then(function (database) {
    if (!database) return '';
    return new Promise(function (resolve) {
      try {
        const request = database.transaction(STUDENT_PHOTO_STORE, 'readonly').objectStore(STUDENT_PHOTO_STORE).get(storageKey);
        request.onsuccess = function () {
          resolve(request.result || '');
        };
        request.onerror = function () {
          resolve('');
        };
      } catch (error) {
        resolve('');
      }
    });
  });
}
function storeStudentPhoto(storageKey, photoData) {
  if (!storageKey || !photoData) return;
  openStudentPhotoDatabase().then(function (database) {
    if (!database) return;
    try {
      database.transaction(STUDENT_PHOTO_STORE, 'readwrite').objectStore(STUDENT_PHOTO_STORE).put(photoData, storageKey);
    } catch (error) {
      // The in-memory cache and normal server loader remain available.
    }
  });
}
window.addEventListener('DOMContentLoaded', function () {
  savedLogoData = STUDIO_STORAGE.getItem(LOGO_KEY) || '';
  activeCardDesign = loadStoredCardDesign(ACTIVE_DESIGN_KEY);
  syncStudentColumnMapping();
  google.script.run.withSuccessHandler(function (configuration) {
    initialConfiguration = configuration || initialConfiguration;
    prepareSetupScreen();
    if (initialConfiguration.hasSpreadsheet) {
      google.script.run.withSuccessHandler(populateRecordsDropdown).withFailureHandler(function (error) {
        showSetupError(error.message || String(error));
      }).getStudentData();
    } else {
      populateRecordsDropdown([]);
    }
  }).withFailureHandler(function (err) {
    showSetupError('Unable to check the saved data sources: ' + (err.message || err));
  }).getAppConfiguration();
});
function prepareSetupScreen() {
  const spreadsheetInput = document.getElementById('spreadsheetUrl');
  const folderInput = document.getElementById('photoFolderUrl');
  const spreadsheetNote = document.getElementById('spreadsheetSourceNote');
  const folderNote = document.getElementById('photoFolderSourceNote');
  if (initialConfiguration.hasSpreadsheet) {
    spreadsheetInput.placeholder = 'Paste another URL or ID to change it';
    spreadsheetNote.textContent = 'Student spreadsheet connected. Saved changes reload when you return to this studio.';
    spreadsheetNote.style.color = '#1f883d';
    document.getElementById('acceptSpreadsheetUrlBtn').textContent = 'Change';
  } else {
    spreadsheetInput.placeholder = 'Paste Google Spreadsheet URL or ID';
    spreadsheetNote.textContent = 'No spreadsheet connected yet.';
    spreadsheetNote.style.color = '#b42318';
    document.getElementById('acceptSpreadsheetUrlBtn').textContent = 'Connect';
  }
  if (initialConfiguration.hasPhotoFolder) {
    folderInput.placeholder = 'Paste another URL or ID to change it';
    folderNote.textContent = 'Student photo folder connected. Photo filenames use Student ID Numbers.';
    folderNote.style.color = '#1f883d';
    document.getElementById('acceptPhotoFolderUrlBtn').textContent = 'Change';
  } else {
    folderInput.placeholder = 'Paste Google Drive folder URL or ID';
    folderNote.textContent = 'No photo folder connected yet.';
    folderNote.style.color = '#b42318';
    document.getElementById('acceptPhotoFolderUrlBtn').textContent = 'Connect';
  }
  if (activeCardDesign) {
    document.getElementById('setupDesignButton').textContent = 'Selected: ' + (activeCardDesign.selectedFileName || activeCardDesign.name);
    document.getElementById('setupDesignNote').textContent = 'Select this button to choose a different .json design file. Review its column mapping before use.';
    document.getElementById('setupDesignNote').style.color = '#1f883d';
  } else {
    document.getElementById('setupDesignButton').textContent = 'Select Card Design';
    document.getElementById('setupDesignNote').textContent = 'Choose a .json design file saved in Design Studio, then map its data elements below.';
    document.getElementById('setupDesignNote').style.color = '#667085';
  }
  if (!initialConfiguration.hasSpreadsheet || !initialConfiguration.hasPhotoFolder || !activeCardDesign) {
    document.getElementById('studentDataSources').open = true;
  }
  updateStudentMappingState();
}
function normalizeSelectedCardDesign(design, fileName) {
  if (!design || design.fileType !== 'ID_CARD_DESIGN' || !Array.isArray(design.elements) && !Array.isArray(design.frontElements) && !Array.isArray(design.backElements)) return null;
  design.frontElements = Array.isArray(design.frontElements) ? design.frontElements : Array.isArray(design.elements) ? design.elements : [];
  design.backElements = Array.isArray(design.backElements) ? design.backElements : [];
  design.elements = design.frontElements;
  design.dataSource = 'student';
  if (fileName && fileName !== 'ID Card Design') design.selectedFileName = fileName;
  if (!String(design.name || '').trim()) {
    design.name = String(fileName || '').replace(/\\.json$/i, '') || 'ID Card Design';
  }
  return design;
}
function loadStoredCardDesign(storageKey) {
  try {
    const design = JSON.parse(STUDIO_STORAGE.getItem(storageKey) || 'null');
    return normalizeSelectedCardDesign(design, 'ID Card Design');
  } catch (error) {
    return null;
  }
}
function syncStudentColumnMapping() {
  studentColumnMap = activeCardDesign ? CardDesignRuntime.loadColumnMapping(activeCardDesign, 'student') : {};
  if (activeCardDesign) {
    CardDesignRuntime.applyColumnMapping(activeCardDesign, studentColumnMap);
  }
  updateStudentMappingState();
}
function updateStudentMappingState() {
  const button = document.getElementById('studentMappingButton');
  const note = document.getElementById('studentMappingNote');
  if (!button || !note) return;
  button.disabled = false;
  button.textContent = 'Design Mapping';
  note.textContent = 'Select a design, worksheet, header option, and columns together.';
}

function openStudentColumnMapping(onlyIfNeeded) {
  StudioReliability.openDesignMapping({
    design: activeCardDesign
  });
}
function studentMappedValue(record, type, fallbackValue) {
  if (activeCardDesign && record) {
    const value = CardDesignRuntime.getLinkedValue(activeCardDesign, record, type);
    if (String(value || '').trim()) return String(value).trim();
  }
  return String(fallbackValue == null ? '' : fallbackValue).trim();
}
function studentDropdownName(record) {
  record = record || {};
  const first = studentMappedValue(record, 'firstName', record.firstName);
  const middle = studentMappedValue(record, 'middleName', record.middleName);
  const last = studentMappedValue(record, 'lastName', record.lastName);
  const full = studentMappedValue(record, 'fullName', record.fullName);
  const parts = [first, middle, last].filter(Boolean).join(' ');
  return first && last ? parts : full || parts || 'Unnamed Student';
}
function studentMappedFullName(record) {
  record = record || {};
  const firstName = studentMappedValue(record, 'firstName', record.firstName);
  const lastName = studentMappedValue(record, 'lastName', record.lastName);
  const fullName = studentMappedValue(record, 'fullName', record.fullName);
  // Separate name mappings take precedence over a partial Full Name value.
  if (firstName && lastName) return firstName + ' ' + lastName;
  if (fullName) return fullName;
  return firstName || lastName || 'Unnamed Student';
}
function selectStudentCardDesign(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function (loadEvent) {
    try {
      const design = normalizeSelectedCardDesign(JSON.parse(loadEvent.target.result), file.name);
      if (!design) throw new Error('Choose a .json design file saved by Design Studio.');
      activeCardDesign = design;
      STUDIO_STORAGE.setItem(ACTIVE_DESIGN_KEY, JSON.stringify(design));
      syncStudentColumnMapping();
      document.getElementById('setupDesignButton').textContent = 'Selected: ' + (design.selectedFileName || design.name);
      document.getElementById('setupDesignNote').textContent = 'Select this button to choose a different .json design file. Review its column mapping before use.';
      document.getElementById('setupDesignNote').style.color = '#1f883d';
      document.getElementById('setupStatus').textContent = '';
      const selectedIndex = document.getElementById('recordSelect').value;
      if (selectedIndex !== '' && recordsList[selectedIndex]) renderSingleCard(recordsList[selectedIndex]);else renderEmptyStudentCard();
      openStudentColumnMapping(true);
    } catch (error) {
      document.getElementById('setupStatus').textContent = error.message || String(error);
    }
  };
  reader.readAsText(file);
  event.target.value = '';
}

/*
 * Removes transparent or white outer margins from an uploaded logo.
 * This makes the actual artwork use the full printable header area.
 */

function showSetupError(message) {
  const status = document.getElementById('setupStatus');
  status.style.color = '#b42318';
  status.textContent = message;
}

function acceptSpreadsheetUrl() {
  const input = document.getElementById('spreadsheetUrl');
  const url = input.value.trim();
  if (!url) {
    alert('Enter a spreadsheet URL or ID first.');
    return;
  }
  StudioReliability.openDesignMapping({
    spreadsheetUrl: url,
    design: activeCardDesign
  });
}
function acceptPhotoFolderUrl() {
  const input = document.getElementById('photoFolderUrl');
  const button = document.getElementById('acceptPhotoFolderUrlBtn');
  const url = input.value.trim();
  if (!url) {
    alert('Paste the student photo folder URL or ID in Data Sources.');
    return;
  }
  button.disabled = true;
  const status = document.getElementById('setupStatus');
  status.style.color = '#667085';
  status.textContent = 'Connecting student photo folder...';
  google.script.run.withSuccessHandler(function (result) {
    StudioReliability.carryDesignToScope(result && result.scope);
    button.disabled = false;
    input.value = '';
    Object.keys(studentPhotoCache).forEach(function (key) {
      delete studentPhotoCache[key];
    });
    initialConfiguration.hasPhotoFolder = true;
    prepareSetupScreen();
    status.style.color = '#1f883d';
    status.textContent = 'Student photo folder connected successfully.';
    StudioReliability.reopen();
    return;
  }).withFailureHandler(function (err) {
    button.disabled = false;
    status.style.color = '#b42318';
    status.textContent = 'Photo folder not changed: ' + (err.message || err);
  }).setPhotoFolderUrl(url);
}
function openSavedResource(resourceType) {
  const newTab = window.open('about:blank', '_blank');
  if (!newTab) {
    alert('Allow pop-ups for this app, then open the spreadsheet or photo folder again.');
    return;
  }
  google.script.run.withSuccessHandler(function (url) {
    newTab.location.href = url;
  }).withFailureHandler(function (error) {
    newTab.close();
    alert(error.message || String(error));
  }).getConfiguredResourceUrl('student', resourceType);
}
function openMissingPhotoList() {
  document.getElementById('missingPhotoModal').hidden = false;
  loadMissingPhotoList();
}
function closeMissingPhotoList() {
  document.getElementById('missingPhotoModal').hidden = true;
}
function loadMissingPhotoList() {
  const button = document.getElementById('refreshMissingPhotosButton');
  const summary = document.getElementById('missingPhotoSummary');
  const tableBody = document.getElementById('missingPhotoTableBody');
  button.disabled = true;
  summary.style.color = '#344054';
  summary.textContent = 'Checking spreadsheet records and photo files…';
  tableBody.innerHTML = '<tr><td colspan="4">Loading…</td></tr>';
  google.script.run.withSuccessHandler(function (report) {
    button.disabled = false;
    renderMissingPhotoReport(report || {});
  }).withFailureHandler(function (error) {
    button.disabled = false;
    missingPhotoReport = [];
    missingPhotoStudentTotal = 0;
    summary.style.color = '#b42318';
    summary.textContent = 'Unable to create the missing-photo list: ' + (error && error.message ? error.message : String(error));
    tableBody.innerHTML = '<tr><td class="missing-photo-empty" colspan="4" style="color:#b42318">Photo check failed.</td></tr>';
  }).getStudentsMissingPhotos();
}
function renderMissingPhotoReport(report) {
  missingPhotoReport = Array.isArray(report.missingPhotos) ? report.missingPhotos : [];
  missingPhotoStudentTotal = Number(report.totalStudents || 0);
  const summary = document.getElementById('missingPhotoSummary');
  const tableBody = document.getElementById('missingPhotoTableBody');
  tableBody.innerHTML = '';
  if (!missingPhotoReport.length) {
    summary.style.color = '#1f883d';
    summary.textContent = 'All ' + missingPhotoStudentTotal + ' students have a matching photo.';
    tableBody.innerHTML = '<tr><td class="missing-photo-empty" colspan="4">No missing student photos were found.</td></tr>';
    return;
  }
  summary.style.color = '#b42318';
  summary.textContent = missingPhotoReport.length + ' of ' + missingPhotoStudentTotal + ' students do not have a matching photo.';
  missingPhotoReport.forEach(function (student) {
    const row = document.createElement('tr');
    [student.idNumber, student.firstName, student.lastName, student.grade].forEach(function (value) {
      const cell = document.createElement('td');
      cell.textContent = value || '—';
      row.appendChild(cell);
    });
    tableBody.appendChild(row);
  });
}
function printMissingPhotoList() {
  if (!missingPhotoReport.length) {
    alert('There are no missing student photos to print.');
    return;
  }
  const printWindow = window.open('', 'missingPhotoPrintWindow', 'width=900,height=700');
  if (!printWindow) {
    alert('Please allow pop-ups to print the missing-photo list.');
    return;
  }
  const rows = missingPhotoReport.map(function (student) {
    return '<tr><td>' + escapeHtml(student.idNumber || '—') + '</td><td>' + escapeHtml(student.firstName || '—') + '</td><td>' + escapeHtml(student.lastName || '—') + '</td><td>' + escapeHtml(student.grade || '—') + '</td></tr>';
  }).join('');
  printWindow.document.open();
  printWindow.document.write('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Students Missing Photos</title><style>@page{size:letter portrait;margin:.5in}body{margin:0;color:#172033;font-family:Arial,sans-serif}h1{margin:0 0 5px;font-size:22px}p{margin:0 0 18px;color:#475467;font-size:12px}table{width:100%;border-collapse:collapse}th,td{padding:8px 9px;border:1px solid #cfd7e2;text-align:left;font-size:11px}th{background:#edf2f7;text-transform:uppercase;font-size:9px;letter-spacing:.05em}</style></head><body><h1>Students Missing Photos</h1><p>' + missingPhotoReport.length + ' of ' + missingPhotoStudentTotal + ' students do not have a matching photo.</p><table><thead><tr><th>Student ID</th><th>First Name</th><th>Last Name</th><th>Grade Level</th></tr></thead><tbody>' + rows + '</tbody></table></body></html>');
  printWindow.document.close();
  printWindow.addEventListener('load', function () {
    printWindow.focus();
    printWindow.print();
  }, {
    once: true
  });
}
function downloadMissingPhotoCsv() {
  if (!missingPhotoReport.length) {
    alert('There are no missing student photos to download.');
    return;
  }
  function csvCell(value) {
    return '"' + String(value == null ? '' : value).replace(/"/g, '""') + '"';
  }
  const rows = [['Student ID', 'First Name', 'Last Name', 'Grade Level']].concat(missingPhotoReport.map(function (student) {
    return [student.idNumber, student.firstName, student.lastName, student.grade];
  }));
  const csv = '\\ufeff' + rows.map(function (row) {
    return row.map(csvCell).join(',');
  }).join('\\r\\n');
  const blob = new Blob([csv], {
    type: 'text/csv;charset=utf-8'
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'students-missing-photos.csv';
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(function () {
    URL.revokeObjectURL(url);
  }, 1000);
}
function openAddStudentPopup() {
  openStudentDataPopup(null);
}
function openEditStudentPopup() {
  const select = document.getElementById('recordSelect');
  const student = recordsList[Number(select.value)];
  if (!student) return alert('Please select a student first.');
  openStudentDataPopup(student);
}
function openStudentDataPopup(initialStudent) {
  if (addStudentWindow && !addStudentWindow.closed) {
    addStudentWindow.focus();
    return;
  }
  const editing = Boolean(initialStudent);
  const originalId = editing ? String(initialStudent.recordKey || '').trim() : '';
  const initialPayload = encodeURIComponent(JSON.stringify(initialStudent || null));
  const linkedFieldsPayload = encodeURIComponent(JSON.stringify(CardDesignRuntime.linkedFormFields(activeCardDesign, spreadsheetHeaders, initialStudent && Array.isArray(initialStudent._row) ? initialStudent._row : [], [], studentColumnMap)));
  addStudentWindow = window.open('', 'addStudentWindow', 'width=520,height=650');
  if (!addStudentWindow) {
    alert('Please allow pop-ups to add a student.');
    return;
  }
  addStudentWindow.document.open();
  addStudentWindow.document.write(\`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>\${editing ? 'Edit Student' : 'Add Student'}</title>
<style>
* {
  box-sizing: border-box;
}
body {
  min-height: 100vh;
  margin: 0;
  padding: 24px;
  font-family: "Segoe UI", Arial, sans-serif;
  color: #24292f;
  background: #eef2f5;
}
.form-card {
  width: 100%;
  max-width: 440px;
  margin: 0 auto;
  padding: 22px;
  background: #fff;
  border: 1px solid #d0d7de;
  border-radius: 12px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, .12);
}
h1 {
  margin: 0 0 18px;
  font-size: 22px;
  color: #6f42c1;
}
.field {
  margin-bottom: 13px;
}
label {
  display: block;
  margin-bottom: 5px;
  font-size: 13px;
  font-weight: 700;
}
input, select {
  width: 100%;
  padding: 9px 10px;
  font-size: 14px;
  background: #fff;
  border: 1px solid #c8d0d8;
  border-radius: 6px;
  outline: none;
}
input:focus, select:focus {
  border-color: #6f42c1;
  box-shadow: 0 0 0 2px rgba(111, 66, 193, .18);
}
.button-row {
  display: flex;
  gap: 10px;
  margin-top: 18px;
}
button {
  flex: 1;
  padding: 10px 14px;
  color: #fff;
  font-size: 14px;
  font-weight: 700;
  border: 0;
  border-radius: 6px;
  cursor: pointer;
}
button:disabled {
  opacity: .6;
  cursor: wait;
}
#cancelBtn {
  background: #6c757d;
}
#deleteBtn {
  background: #b42318;
}
#saveBtn {
  background: #1f883d;
}
#saveBtn {
  order: 1;
}
#deleteBtn {
  order: 2;
}
#cancelBtn {
  order: 3;
}
#statusText {
  min-height: 20px;
  margin: 12px 0 0;
  font-size: 13px;
  font-weight: 600;
  color: #b42318;
}
</style>
</head>
<body>
<form class="form-card" id="studentForm">
<h1>\${editing ? 'Edit Student' : 'Add Student'}</h1>
<p style="margin:-8px 0 16px;color:#57606a;font-size:12px;line-height:1.45">These fields come from the mapped data elements on both sides of your selected design. Save writes the values to the connected student spreadsheet.</p>
<div id="designLinkedFields">
</div>
<div class="button-row">
<button type="submit" id="saveBtn" title="Save the entered values to the connected student spreadsheet.">Save</button>
<button type="button" id="deleteBtn" \${editing ? '' : 'hidden'} title="Delete this spreadsheet record and move matching photos to Drive Trash.">Delete</button>
<button type="button" id="cancelBtn" title="Close without saving these changes.">Cancel</button>
</div>
<p id="statusText">
</p>
</form>
<script>
const form = document.getElementById('studentForm');
const saveButton = document.getElementById('saveBtn');
const statusText = document.getElementById('statusText');
const initialStudent = JSON.parse(decodeURIComponent('\${initialPayload}'));
const linkedFields = JSON.parse(decodeURIComponent('\${linkedFieldsPayload}'));
const originalId = '\${originalId.replace(/'/g, "\\\\'")}';
const linkedFieldsHost = document.getElementById('designLinkedFields');
if (!linkedFields.length) {
  const message = document.createElement('p');
  message.style.color = '#b42318';
  message.style.fontWeight = '700';
  message.textContent = 'No data fields are mapped for this design. Open Data Sources → Design Mapping, choose the columns, and save the mapping.';
  linkedFieldsHost.appendChild(message);
  saveButton.disabled = true;
}
linkedFields.forEach(function (field) {
  const wrapper = document.createElement('div');
  wrapper.className = 'field';
  const label = document.createElement('label');
  label.htmlFor = 'linkedColumn' + field.columnIndex;
  label.textContent = field.label;
  const input = document.createElement('input');
  input.type = 'text';
  input.id = 'linkedColumn' + field.columnIndex;
  input.dataset.columnIndex = String(field.columnIndex);
  input.dataset.fieldType = field.type;
  input.value = field.value || '';
  wrapper.appendChild(label);
  wrapper.appendChild(input);
  linkedFieldsHost.appendChild(wrapper);
});
if (initialStudent) saveButton.textContent = 'Save';
document.getElementById('cancelBtn').addEventListener('click', function () {
  window.close();
});
document.getElementById('deleteBtn').addEventListener('click', function () {
  if (!originalId) return;
  const fullName = (initialStudent && initialStudent.firstName || '') + ' ' + (initialStudent && initialStudent.lastName || '');
  if (!confirm('Delete ' + fullName.trim() + ' from the spreadsheet and move matching photos to Drive Trash? The app cannot undo this deletion.')) return;
  this.disabled = true;
  saveButton.disabled = true;
  statusText.style.color = '#57606a';
  statusText.textContent = 'Deleting student and photo...';
  window.opener.postMessage({
    sessionToken: window.__STUDIO_TOKEN,
    type: 'DELETE_STUDENT',
    originalId: originalId
  }, '*');
});
form.addEventListener('submit', function (event) {
  event.preventDefault();
  if (!form.reportValidity()) return;
  const columnValues = {};
  linkedFieldsHost.querySelectorAll('[data-column-index]').forEach(function (input) {
    columnValues[input.dataset.columnIndex] = input.value.trim();
  });
  const student = {
    columnValues: columnValues
  };
  if (!Object.values(columnValues).some(Boolean)) {
    statusText.textContent = 'Enter data in at least one mapped field.';
    return;
  }
  saveButton.disabled = true;
  statusText.style.color = '#57606a';
  statusText.textContent = originalId ? 'Updating student...' : 'Saving student...';
  window.opener.postMessage({
    sessionToken: window.__STUDIO_TOKEN,
    type: 'SAVE_STUDENT',
    originalId: originalId,
    student: student
  }, '*');
});
window.addEventListener('message', function (event) {
  if (!event.data || event.data.type !== 'SAVE_STUDENT_RESULT' || event.source !== window.opener) return;
  if (event.data.success) {
    statusText.style.color = '#1f883d';
    statusText.textContent = originalId ? 'Student updated successfully.' : 'Student saved successfully.';
    setTimeout(function () {
      window.close();
    }, 700);
  } else {
    saveButton.disabled = false;
    statusText.style.color = '#b42318';
    statusText.textContent = event.data.error || 'Unable to save the student.';
  }
});
window.addEventListener('message', function (event) {
  if (!event.data || event.data.type !== 'DELETE_STUDENT_RESULT' || event.source !== window.opener) return;
  if (event.data.success) {
    statusText.style.color = '#1f883d';
    statusText.textContent = 'Student and photo deleted.';
    setTimeout(function () {
      window.close();
    }, 500);
  } else {
    document.getElementById('deleteBtn').disabled = false;
    saveButton.disabled = false;
    statusText.style.color = '#b42318';
    statusText.textContent = event.data.error || 'Unable to delete the student.';
  }
});
<\\/script>
</body>
</html>\`);
  addStudentWindow.document.close();
  StudioReliability.registerPopup(addStudentWindow);
}
window.addEventListener('message', function (event) {
  if (!event.data || event.data.type !== 'SAVE_STUDENT') return;
  if (!addStudentWindow || event.source !== addStudentWindow) return;
  const popup = event.source;
  const student = event.data.student;
  const originalId = String(event.data.originalId || '').trim();
  const call = google.script.run.withSuccessHandler(function (response) {
    populateRecordsDropdown(response.students || [], response.savedId);
    if (popup && !popup.closed) {
      popup.postMessage({
        type: 'SAVE_STUDENT_RESULT',
        success: true
      }, '*');
    }
  }).withFailureHandler(function (err) {
    if (popup && !popup.closed) {
      popup.postMessage({
        type: 'SAVE_STUDENT_RESULT',
        success: false,
        error: err.message || String(err)
      }, '*');
    }
  });
  if (originalId) call.updateStudent(student, originalId);else call.addStudent(student);
});
window.addEventListener('message', function (event) {
  if (!event.data || event.data.type !== 'DELETE_STUDENT') return;
  if (!addStudentWindow || event.source !== addStudentWindow) return;
  const popup = event.source;
  const originalId = String(event.data.originalId || '').trim();
  google.script.run.withSuccessHandler(function (response) {
    populateRecordsDropdown(response.students || []);
    if (popup && !popup.closed) popup.postMessage({
      type: 'DELETE_STUDENT_RESULT',
      success: true
    }, '*');
  }).withFailureHandler(function (error) {
    if (popup && !popup.closed) popup.postMessage({
      type: 'DELETE_STUDENT_RESULT',
      success: false,
      error: error.message || String(error)
    }, '*');
  }).deleteStudent(originalId);
});

/*
 * CAMERA FIX:
 * 1. Ask for permission first so camera labels become available.
 * 2. Call enumerateDevices() and fill the dropdown.
 * 3. Restart the stream with the selected deviceId when it changes.
 */
let studentCameraWindow = null;
let cameraStudentId = "";
function openCamera() {
  if (!activeStudentId) {
    alert('Select a student before taking a photo.');
    return;
  }
  const camWindow = window.open('', 'studentCameraWindow', 'width=760,height=760');
  studentCameraWindow = camWindow;
  cameraStudentId = activeStudentId;
  if (!camWindow) {
    alert('Please allow pop-ups to open the camera.');
    return;
  }
  camWindow.document.open();
  camWindow.document.write(\`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Take Student Photo</title>
<style>
* {
  box-sizing: border-box;
}
body {
  min-height: 100vh;
  margin: 0;
  padding: 18px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  font-family: Arial, sans-serif;
  color: #fff;
  background: #111827;
}
.controls {
  width: 100%;
  max-width: 560px;
}
select {
  width: 100%;
  padding: 10px;
  color: #fff;
  background: #202938;
  border: 1px solid #4b5563;
  border-radius: 7px;
  font-size: 14px;
}
.id-photo-frame {
  width: 330px;
  height: 440px;
  max-width: 90vw;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  background: #000;
  border: 2px solid #4b5563;
  border-radius: 12px;
}
.id-photo-frame video, .id-photo-frame img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}
.button-row {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 9px;
}
.btn-action {
  min-width: 110px;
  padding: 10px 14px;
  color: #fff;
  font-size: 14px;
  font-weight: 700;
  border: 0;
  border-radius: 7px;
  cursor: pointer;
}
.btn-action:disabled {
  opacity: .55;
  cursor: not-allowed;
}
#captureBtn {
  background: #7141c6;
}
#retakeBtn {
  display: none;
  background: #e67e22;
}
#saveBtn {
  background: #1f883d;
}
#cancelBtn {
  background: #6b7280;
}
#statusText {
  min-height: 18px;
  margin: 0;
  color: #fdba74;
  text-align: center;
  font-size: 13px;
}
</style>
</head>
<body>
<div class="controls">
<select id="cameraSelect" disabled>
<option value="">Loading cameras...</option>
</select>
</div>
<p id="statusText">Allow camera access when prompted, then choose a camera.</p>
<div class="id-photo-frame">
<video id="cameraStream" autoplay playsinline muted>
</video>
<img id="photoPreview" alt="Captured photo preview" style="display:none">
</div>
<div class="button-row">
<button id="captureBtn" class="btn-action" disabled title="Capture the current camera image for review.">Capture Photo</button>
<button id="retakeBtn" class="btn-action" title="Discard the captured image and return to the camera.">Retake Photo</button>
<button id="saveBtn" class="btn-action" disabled title="Save this photo to the connected photo folder for the selected record.">Save Photo</button>
<button id="cancelBtn" class="btn-action" title="Close without saving these changes.">Cancel</button>
</div>
<script>
const video = document.getElementById('cameraStream');
const previewImg = document.getElementById('photoPreview');
const cameraSelect = document.getElementById('cameraSelect');
const captureBtn = document.getElementById('captureBtn');
const retakeBtn = document.getElementById('retakeBtn');
const saveBtn = document.getElementById('saveBtn');
const statusText = document.getElementById('statusText');
let currentStream = null;
let capturedImageDataUrl = '';
function stopCurrentStream() {
  if (currentStream) {
    currentStream.getTracks().forEach(function (track) {
      track.stop();
    });
    currentStream = null;
  }
}
async function loadCameraList(selectedDeviceId) {
  const devices = await navigator.mediaDevices.enumerateDevices();
  const cameras = devices.filter(function (device) {
    return device.kind === 'videoinput';
  });
  cameraSelect.innerHTML = '';
  if (!cameras.length) {
    cameraSelect.innerHTML = '<option value="">No camera found</option>';
    cameraSelect.disabled = true;
    throw new Error('No camera was found on this device.');
  }
  cameras.forEach(function (camera, index) {
    const option = document.createElement('option');
    option.value = camera.deviceId;
    option.textContent = camera.label || 'Camera ' + (index + 1);
    cameraSelect.appendChild(option);
  });
  if (selectedDeviceId && cameras.some(function (camera) {
    return camera.deviceId === selectedDeviceId;
  })) {
    cameraSelect.value = selectedDeviceId;
  }
  cameraSelect.disabled = cameras.length < 2;
}
async function startCamera(deviceId) {
  stopCurrentStream();
  captureBtn.disabled = true;
  statusText.textContent = 'Starting camera...';
  const videoConstraints = deviceId ? {
    deviceId: {
      exact: deviceId
    },
    width: {
      ideal: 1280
    },
    height: {
      ideal: 720
    }
  } : {
    width: {
      ideal: 1280
    },
    height: {
      ideal: 720
    }
  };
  try {
    currentStream = await navigator.mediaDevices.getUserMedia({
      video: videoConstraints,
      audio: false
    });
    video.srcObject = currentStream;
    await video.play();
    const activeTrack = currentStream.getVideoTracks()[0];
    const settings = activeTrack.getSettings ? activeTrack.getSettings() : {};
    await loadCameraList(settings.deviceId || deviceId || '');
    video.style.display = 'block';
    previewImg.style.display = 'none';
    captureBtn.style.display = 'inline-block';
    retakeBtn.style.display = 'none';
    captureBtn.disabled = false;
    saveBtn.disabled = true;
    statusText.textContent = '';
  } catch (err) {
    console.error(err);
    cameraSelect.innerHTML = '<option value="">Camera unavailable</option>';
    cameraSelect.disabled = true;
    captureBtn.disabled = true;
    statusText.textContent = 'Camera error: ' + (err.message || err.name || err);
  }
}
cameraSelect.addEventListener('change', function () {
  capturedImageDataUrl = '';
  startCamera(cameraSelect.value);
});
captureBtn.addEventListener('click', function () {
  if (!video.videoWidth || !video.videoHeight) {
    statusText.textContent = 'The camera is not ready yet.';
    return;
  }
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  const targetWidth = 360;
  const targetHeight = 480;
  canvas.width = targetWidth;
  canvas.height = targetHeight;
  const videoAspect = video.videoWidth / video.videoHeight;
  const frameAspect = targetWidth / targetHeight;
  let sourceWidth;
  let sourceHeight;
  let sourceX;
  let sourceY;
  if (videoAspect > frameAspect) {
    sourceHeight = video.videoHeight;
    sourceWidth = sourceHeight * frameAspect;
    sourceX = (video.videoWidth - sourceWidth) / 2;
    sourceY = 0;
  } else {
    sourceWidth = video.videoWidth;
    sourceHeight = sourceWidth / frameAspect;
    sourceX = 0;
    sourceY = (video.videoHeight - sourceHeight) / 2;
  }
  ctx.drawImage(video, sourceX, sourceY, sourceWidth, sourceHeight, 0, 0, targetWidth, targetHeight);
  capturedImageDataUrl = canvas.toDataURL('image/jpeg', 0.9);
  previewImg.src = capturedImageDataUrl;
  video.style.display = 'none';
  previewImg.style.display = 'block';
  captureBtn.style.display = 'none';
  retakeBtn.style.display = 'inline-block';
  saveBtn.disabled = false;
  statusText.textContent = '';
});
retakeBtn.addEventListener('click', function () {
  capturedImageDataUrl = '';
  previewImg.src = '';
  previewImg.style.display = 'none';
  video.style.display = 'block';
  retakeBtn.style.display = 'none';
  captureBtn.style.display = 'inline-block';
  saveBtn.disabled = true;
});
saveBtn.addEventListener('click', function () {
  if (!capturedImageDataUrl) {
    alert('Select Capture Photo before saving.');
    return;
  }
  if (!window.opener) {
    alert('The main ID-card window is no longer available.');
    return;
  }
  window.opener.postMessage({
    sessionToken: window.__STUDIO_TOKEN,
    type: 'CAPTURED_PHOTO',
    dataUrl: capturedImageDataUrl
  }, '*');
  saveBtn.disabled = true;
  statusText.textContent = 'Saving photo...';
});
document.getElementById('cancelBtn').addEventListener('click', function () {
  stopCurrentStream();
  window.close();
});
window.addEventListener('message', function (event) {
  if (!event.data || event.data.type !== 'STUDENT_PHOTO_RESULT' || event.source !== window.opener) return;
  if (event.data.success) {
    stopCurrentStream();
    window.close();
  } else {
    saveBtn.disabled = false;
    statusText.textContent = event.data.error || 'Unable to save photo.';
  }
});
window.addEventListener('beforeunload', stopCurrentStream);
if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
  cameraSelect.innerHTML = '<option value="">Camera not supported</option>';
  statusText.textContent = 'This browser does not support camera access.';
} else {
  startCamera('');
}
<\\/script>
</body>
</html>\`);
  camWindow.document.close();
  StudioReliability.registerPopup(camWindow);
}

/* One global listener handles both preview and Drive saving. */
window.addEventListener('message', function (event) {
  if (!event.data || event.data.type !== 'CAPTURED_PHOTO' || !studentCameraWindow || event.source !== studentCameraWindow) return;
  const capturedDataUrl = event.data.dataUrl;
  const studentId = cameraStudentId;
  const popup = event.source;
  if (!studentId) {
    if (popup && !popup.closed) popup.postMessage({
      type: 'STUDENT_PHOTO_RESULT',
      success: false,
      error: 'Please select a student before saving the photo.'
    }, '*');
    return;
  }
  const designedCard = Array.from(document.querySelectorAll('.album-design-card')).find(function (card) {
    return card.dataset.recordId === studentId;
  });
  const designedStudent = recordsList.find(function (record) {
    return String(record.recordKey || '') === studentId;
  });
  studentPhotoCache[String(studentId).trim().toLowerCase()] = capturedDataUrl;
  if (designedStudent && activeCardDesign) {
    const designedPhotoKey = CardDesignRuntime.getPhotoKey(activeCardDesign, designedStudent);
    if (designedPhotoKey) {
      studentPhotoCache[String(designedPhotoKey).trim().toLowerCase()] = capturedDataUrl;
    }
  }
  if (designedCard && designedStudent && activeCardDesign) {
    CardDesignRuntime.render(designedCard.parentElement, activeCardDesign, designedStudent, {
      recordId: studentId,
      logoData: activeCardDesign.logoData || savedLogoData,
      photoData: capturedDataUrl
    });
  }
  google.script.run.withSuccessHandler(function (response) {
    if (!response || !response.success) {
      if (popup && !popup.closed) popup.postMessage({
        type: 'STUDENT_PHOTO_RESULT',
        success: false,
        error: response && response.error || 'Unable to save photo.'
      }, '*');
      return;
    }
    if (popup && !popup.closed) popup.postMessage({
      type: 'STUDENT_PHOTO_RESULT',
      success: true
    }, '*');
  }).withFailureHandler(function (err) {
    if (popup && !popup.closed) popup.postMessage({
      type: 'STUDENT_PHOTO_RESULT',
      success: false,
      error: err.message || String(err)
    }, '*');
  }).saveStudentPhoto(capturedDataUrl, studentId);
});
function searchStudentByFullName() {
  const input = document.getElementById('studentNameSearchInput');
  const query = input.value.trim();
  if (!query) return;
  const matches = CardDesignRuntime.matchingRecords(activeCardDesign, recordsList, query, false);
  if (!matches.length) {
    alert('No matching records were found for: ' + query);
    return;
  }
  const select = document.getElementById('recordSelect');
  select.value = '';
  activeStudentId = '';
  if (matches.length === 1) {
    select.value = String(recordsList.indexOf(matches[0]));
    handleRecordSelect(select);
  } else renderMultipleCards(matches);
  window.activeNameSearch = query;
  input.value = '';
}
function searchStudentById() {
  const searchInput = document.getElementById('idSearchInput');
  const searchValue = searchInput.value.trim().toLowerCase();
  if (!searchValue) return;
  const foundIndex = recordsList.findIndex(function (record) {
    const idNumber = studentMappedValue(record, 'idNumber', record.idNumber);
    return idNumber && idNumber.toLowerCase().indexOf(searchValue) !== -1;
  });
  if (foundIndex === -1) {
    alert('No student was found with this ID number: ' + searchValue);
    return;
  }
  const select = document.getElementById('recordSelect');
  select.value = String(foundIndex);
  handleRecordSelect(select);
  searchInput.value = '';
}
function searchStudentByGrade() {
  const searchInput = document.getElementById('gradeSearchInput');
  const searchValue = searchInput.value.trim().toLowerCase();
  if (!searchValue) return;
  const matchingStudents = recordsList.filter(function (record) {
    const grade = studentMappedValue(record, 'class', record.grade);
    return grade && grade.toLowerCase() === searchValue;
  });
  if (!matchingStudents.length) {
    alert('No students were found in grade level: ' + searchValue);
    return;
  }
  activeStudentId = '';
  window.activeNameSearch = '';
  document.getElementById('recordSelect').value = '';
  renderMultipleCards(matchingStudents);
  searchInput.value = '';
}
function populateRecordsDropdown(records, preferredId) {
  recordsList = records || [];
  syncStudentPrintList();
  updateStudentMappingState();
  if (recordsList.length && Array.isArray(recordsList[0]._headers)) {
    spreadsheetHeaders = recordsList[0]._headers.slice();
  } else {
    google.script.run.withSuccessHandler(function (headers) {
      spreadsheetHeaders = Array.isArray(headers) ? headers : [];
      updateStudentMappingState();
    }).getConfiguredSpreadsheetHeaders('student');
  }
  const select = document.getElementById('recordSelect');
  select.innerHTML = '<option value="">Select Student</option>';
  recordsList.forEach(function (record, index) {
    const option = document.createElement('option');
    option.value = String(index);
    const displayId = studentMappedValue(record, 'idNumber', record.idNumber);
    option.textContent = studentDropdownName(record) + (displayId ? ' (' + displayId + ')' : '');
    select.appendChild(option);
  });
  const requestedId = String(preferredId || '').trim();
  if (recordsList.length && requestedId) {
    const preferredIndex = recordsList.findIndex(function (record) {
      return String(record.recordKey || '') === requestedId;
    });
    if (preferredIndex !== -1) {
      select.value = String(preferredIndex);
      activeStudentId = String(recordsList[preferredIndex].recordKey || '');
      renderSingleCard(recordsList[preferredIndex]);
      return;
    }
  }
  select.value = '';
  activeStudentId = '';
  renderEmptyStudentCard();
}
function renderEmptyStudentCard() {
  const wrapper = document.getElementById('cardsWrapper');
  studentPreviewRequest += 1;
  setStudentPreviewMode(false);
  wrapper.innerHTML = '';
  if (!activeCardDesign) {
    return;
  }
  const mount = document.createElement('div');
  mount.className = 'album-card-mount empty-student-card';
  mount.id = 'empty-student-card';
  wrapper.appendChild(mount);
  CardDesignRuntime.render(mount, activeCardDesign, {}, {
    recordId: '',
    logoData: activeCardDesign.logoData || savedLogoData,
    photoLoading: false,
    emptyPreview: true
  });
}
function handleRecordSelect(selectElement) {
  window.activeNameSearch = '';
  const index = selectElement.value;
  if (index === '' || !recordsList[index]) {
    activeStudentId = '';
    renderEmptyStudentCard();
    return;
  }
  const person = recordsList[index];
  activeStudentId = String(person.recordKey || '');
  renderSingleCard(person);
}
function renderSingleCard(person) {
  activeStudentId = String(person.recordKey || '');
  renderMultipleCards([person]);
}
function escapeHtml(value) {
  return String(value == null ? '' : value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}
function renderMultipleCards(students) {
  const wrapper = document.getElementById('cardsWrapper');
  const requestToken = ++studentPreviewRequest;
  setStudentPreviewMode(false);
  wrapper.innerHTML = '';
  if (!activeCardDesign) {
    showSetupError('Open Data Sources and select a Student card design (.json) from your device.');
    return;
  }
  const pendingPhotoJobs = [];
  students.forEach(function (person, index) {
    const studentId = String(person.recordKey || '');
    const mount = document.createElement('div');
    mount.className = 'album-card-mount';
    mount.id = 'album-card-' + index;
    studentPrintListCard(person, mount, wrapper);
    const options = {
      recordId: studentId,
      logoData: activeCardDesign.logoData || savedLogoData,
      photoLoading: false
    };
    const photoLookupKey = CardDesignRuntime.getPhotoKey(activeCardDesign, person);
    const cacheKey = String(photoLookupKey || '').trim().toLowerCase();
    if (!photoLookupKey) {
      options.photoData = '';
    } else if (Object.prototype.hasOwnProperty.call(studentPhotoCache, cacheKey)) {
      options.photoData = studentPhotoCache[cacheKey] || '';
      options.photoLoading = false;
    } else {
      options.photoLoading = true;
      pendingPhotoJobs.push({
        person: person,
        mount: mount,
        options: options,
        lookupKey: photoLookupKey,
        requestToken: requestToken,
        cacheKey: cacheKey
      });
    }
    CardDesignRuntime.render(mount, activeCardDesign, person, options);
  });
  if (!pendingPhotoJobs.length) return;
  google.script.run.withSuccessHandler(function (photoMatches) {
    if (requestToken !== studentPreviewRequest) return;
    const matches = Array.isArray(photoMatches) ? photoMatches : [];
    const cacheChecks = pendingPhotoJobs.map(function (job, index) {
      const match = matches[index] || null;
      const fileId = match && typeof match === 'object' ? match.fileId : match;
      const version = match && typeof match === 'object' ? match.version : 'legacy';
      if (!fileId) {
        job.options.photoData = '';
        job.options.photoLoading = false;
        job.options.photoError = Boolean(match && match.error);
        if (job.requestToken === undefined || job.requestToken === studentPreviewRequest) CardDesignRuntime.render(job.mount, activeCardDesign, job.person, job.options);
        return Promise.resolve(null);
      }
      job.fileId = fileId;
      job.storageKey = String(fileId) + ':' + String(version || 'current');
      return readStoredStudentPhoto(job.storageKey).then(function (photoData) {
        if (!photoData) return job;
        studentPhotoCache[job.cacheKey] = photoData;
        job.options.photoData = photoData;
        job.options.photoLoading = false;
        job.options.photoError = Boolean(match && match.error);
        CardDesignRuntime.render(job.mount, activeCardDesign, job.person, job.options);
        return null;
      });
    });
    Promise.all(cacheChecks).then(function (results) {
      loadStudentPhotoQueue(results.filter(function (job) {
        return Boolean(job);
      }));
    });
  }).withFailureHandler(function (error) {
    if (requestToken !== studentPreviewRequest) return;
    pendingPhotoJobs.forEach(function (job) {
      job.options.photoLoading = false;
      job.options.photoError = true;
      CardDesignRuntime.render(job.mount, activeCardDesign, job.person, job.options);
    });
    const status = document.getElementById('setupStatus');
    status.style.color = '#b42318';
    status.textContent = 'Student photos could not be loaded: ' + (error && error.message ? error.message : String(error));
  }).getStudentPhotoManifest(pendingPhotoJobs.map(function (job) {
    return job.lookupKey;
  }));
}

/*
 * Loads a maximum of four optimized images at once. Photos appear progressively,
 * while the request count remains safely below browser and Apps Script
 * concurrency limits. A failed photo is retried once automatically.
 */
function loadStudentPhotoQueue(photoJobs) {
  if (!photoJobs.length) return;
  const maximumConcurrentPhotos = 4;
  let nextJobIndex = 0;
  let activeRequests = 0;
  let completedRequests = 0;
  let failedRequests = 0;
  function finishJob(job, photoData, failed) {
    if (photoData) {
      studentPhotoCache[job.cacheKey] = photoData;
      storeStudentPhoto(job.storageKey, photoData);
    }
    job.options.photoData = photoData || '';
    job.options.photoLoading = false;
    job.options.photoError = Boolean(failed);
    CardDesignRuntime.render(job.mount, activeCardDesign, job.person, job.options);
    activeRequests -= 1;
    completedRequests += 1;
    if (failed) failedRequests += 1;
    if (completedRequests === photoJobs.length && failedRequests > 0) {
      const status = document.getElementById('setupStatus');
      status.style.color = '#b42318';
      status.textContent = failedRequests + ' student photo' + (failedRequests === 1 ? '' : 's') + ' could not be loaded. Please try the grade again.';
    }
    startAvailableJobs();
  }
  function requestPhoto(job, attemptNumber) {
    google.script.run.withSuccessHandler(function (photoData) {
      finishJob(job, photoData || '', false);
    }).withFailureHandler(function () {
      if (attemptNumber < 1) {
        window.setTimeout(function () {
          requestPhoto(job, attemptNumber + 1);
        }, 350);
        return;
      }
      finishJob(job, '', true);
    }).getStudentPhotoByFileId(job.fileId);
  }
  function startAvailableJobs() {
    while (activeRequests < maximumConcurrentPhotos && nextJobIndex < photoJobs.length) {
      const job = photoJobs[nextJobIndex];
      nextJobIndex += 1;
      activeRequests += 1;
      requestPhoto(job, 0);
    }
  }
  startAvailableJobs();
}
function getStudentPrintPhotoManifest(lookupKeys) {
  return new Promise(function (resolve, reject) {
    google.script.run.withSuccessHandler(function (matches) {
      resolve(Array.isArray(matches) ? matches : []);
    }).withFailureHandler(reject).getStudentPhotoManifest(lookupKeys);
  });
}
function loadStudentPrintPhoto(fileId, attemptNumber) {
  return new Promise(function (resolve) {
    google.script.run.withSuccessHandler(function (photoData) {
      resolve({
        photoData: photoData || '',
        failed: false
      });
    }).withFailureHandler(function () {
      if ((attemptNumber || 0) < 1) {
        window.setTimeout(function () {
          loadStudentPrintPhoto(fileId, 1).then(resolve);
        }, 350);
        return;
      }
      resolve({
        photoData: '',
        failed: true
      });
    }).getStudentPhotoByFileId(fileId);
  });
}
function setStudentPreviewMode(showingAll) {
  const wrapper = document.getElementById('cardsWrapper');
  const selectedPrintButton = document.getElementById('printSelectedStudentButton');
  const previewAllButton = document.getElementById('previewAllStudentsButton');
  if (wrapper) wrapper.classList.toggle('previewing-all', Boolean(showingAll));
  if (selectedPrintButton) selectedPrintButton.disabled = false;
  if (!showingAll && previewAllButton) previewAllButton.disabled = false;
}
async function previewAllStudentCards() {
  window.activeNameSearch = '';
  if (!activeCardDesign) {
    alert('Please select a Student card design first.');
    return;
  }
  if (!recordsList.length) {
    alert('There are no student records to preview.');
    return;
  }
  const requestToken = ++studentPreviewRequest;
  const button = document.getElementById('previewAllStudentsButton');
  const wrapper = document.getElementById('cardsWrapper');
  const status = document.createElement('p');
  const grid = document.createElement('div');
  const previewDesign = activeCardDesign;
  const previewLogo = previewDesign.logoData || savedLogoData;
  const pendingJobs = [];
  let completedJobs = 0;
  status.className = 'all-card-preview-status';
  status.textContent = 'Loading photos for 0 of ' + recordsList.length + ' student cards…';
  grid.className = 'all-card-preview-grid';
  wrapper.innerHTML = '';
  setStudentPreviewMode(true);
  wrapper.append(status, grid);
  function updateProgress() {
    if (requestToken !== studentPreviewRequest) return;
    status.textContent = completedJobs < recordsList.length ? 'Loading photos for ' + completedJobs + ' of ' + recordsList.length + ' student cards…' : 'Showing all ' + recordsList.length + ' student ID cards.';
  }
  function finishJob(job, photoData, failed) {
    if (requestToken !== studentPreviewRequest || job.finished) return;
    job.finished = true;
    if (photoData) {
      studentPhotoCache[job.cacheKey] = photoData;
      if (job.storageKey) storeStudentPhoto(job.storageKey, photoData);
    }
    job.options.photoData = photoData || '';
    job.options.photoLoading = false;
    job.options.photoError = Boolean(failed);
    CardDesignRuntime.render(job.mount, previewDesign, job.person, job.options);
    completedJobs += 1;
    updateProgress();
  }
  recordsList.forEach(function (person) {
    const studentId = String(person.recordKey || '');
    const lookupKey = CardDesignRuntime.getPhotoKey(previewDesign, person);
    const cacheKey = String(lookupKey || '').trim().toLowerCase();
    const cardMount = document.createElement('div');
    const options = {
      recordId: studentId,
      logoData: previewLogo,
      photoLoading: Boolean(lookupKey)
    };
    const job = {
      person: person,
      mount: cardMount,
      options: options,
      lookupKey: lookupKey,
      cacheKey: cacheKey,
      storageKey: '',
      finished: false
    };
    studentPrintListCard(person, cardMount, grid);
    CardDesignRuntime.render(cardMount, previewDesign, person, options);
    if (!lookupKey) finishJob(job, '', false);else if (Object.prototype.hasOwnProperty.call(studentPhotoCache, cacheKey)) {
      finishJob(job, studentPhotoCache[cacheKey] || '', false);
    } else pendingJobs.push(job);
  });
  button.disabled = true;
  try {
    if (pendingJobs.length) {
      const matches = await getStudentPrintPhotoManifest(pendingJobs.map(function (job) {
        return job.lookupKey;
      }));
      if (requestToken !== studentPreviewRequest) return;
      const storageChecks = pendingJobs.map(function (job, index) {
        const match = matches[index] || null;
        const fileId = match && typeof match === 'object' ? match.fileId : match;
        const version = match && typeof match === 'object' ? match.version : 'legacy';
        if (!fileId) {
          finishJob(job, '', Boolean(match && match.error));
          return Promise.resolve(null);
        }
        job.fileId = fileId;
        job.storageKey = String(fileId) + ':' + String(version || 'current');
        return readStoredStudentPhoto(job.storageKey).then(function (photoData) {
          if (photoData) {
            finishJob(job, photoData, false);
            return null;
          }
          return job;
        });
      });
      const checkedJobs = await Promise.all(storageChecks);
      if (requestToken !== studentPreviewRequest) return;
      const remoteJobs = checkedJobs.filter(function (job) {
        return Boolean(job);
      });
      let nextRemoteJob = 0;
      const workerCount = Math.min(4, remoteJobs.length);
      async function worker() {
        while (nextRemoteJob < remoteJobs.length && requestToken === studentPreviewRequest) {
          const job = remoteJobs[nextRemoteJob];
          nextRemoteJob += 1;
          const result = await loadStudentPrintPhoto(job.fileId, 0);
          finishJob(job, result.photoData, result.failed);
        }
      }
      await Promise.all(Array.from({
        length: workerCount
      }, function () {
        return worker();
      }));
    }
    updateProgress();
  } catch (error) {
    pendingJobs.forEach(function (job) {
      if (!job.finished) finishJob(job, '', true);
    });
  } finally {
    if (requestToken === studentPreviewRequest) button.disabled = false;
  }
}
async function printAllStudentCards() {
  return printStudentBatch(recordsList.slice(), 'printAllStudentsButton');
}
async function printStudentBatch(printRecords, buttonId) {
  if (!activeCardDesign) {
    alert('Please select a Student card design first.');
    return;
  }
  if (!printRecords.length) {
    alert('There are no student records to print.');
    return;
  }
  const printWindow = CardDesignRuntime.createPrintWindow('Loading photos for ' + printRecords.length + ' student cards…');
  if (!printWindow) return;
  const printDesign = activeCardDesign;
  const printLogo = printDesign.logoData || savedLogoData;
  const button = document.getElementById(buttonId);
  const batchContainer = document.createElement('div');
  const pendingJobs = [];
  let completedJobs = 0;
  function updateProgress() {
    if (printWindow.closed) return;
    const status = printWindow.document.getElementById('printPreparationStatus');
    if (status) {
      status.textContent = 'Loaded ' + completedJobs + ' of ' + printRecords.length + ' student cards…';
    }
  }
  function finishJob(job, photoData, failed) {
    if (job.finished) return;
    job.finished = true;
    if (photoData) {
      studentPhotoCache[job.cacheKey] = photoData;
      if (job.storageKey) storeStudentPhoto(job.storageKey, photoData);
    }
    job.options.photoData = photoData || '';
    job.options.photoLoading = false;
    job.options.photoError = Boolean(failed);
    CardDesignRuntime.render(job.mount, printDesign, job.person, job.options);
    completedJobs += 1;
    updateProgress();
  }
  printRecords.forEach(function (person) {
    const studentId = String(person.recordKey || '');
    const lookupKey = CardDesignRuntime.getPhotoKey(printDesign, person);
    const cacheKey = String(lookupKey || '').trim().toLowerCase();
    const mount = document.createElement('div');
    const options = {
      recordId: studentId,
      logoData: printLogo,
      photoLoading: Boolean(lookupKey)
    };
    const job = {
      person: person,
      mount: mount,
      options: options,
      lookupKey: lookupKey,
      cacheKey: cacheKey,
      storageKey: '',
      finished: false
    };
    batchContainer.appendChild(mount);
    CardDesignRuntime.render(mount, printDesign, person, options);
    if (!lookupKey) {
      finishJob(job, '', false);
    } else if (Object.prototype.hasOwnProperty.call(studentPhotoCache, cacheKey)) {
      finishJob(job, studentPhotoCache[cacheKey] || '', false);
    } else {
      pendingJobs.push(job);
    }
  });
  button.disabled = true;
  try {
    if (pendingJobs.length) {
      const matches = await getStudentPrintPhotoManifest(pendingJobs.map(function (job) {
        return job.lookupKey;
      }));
      const remoteJobs = [];
      pendingJobs.forEach(function (job, index) {
        const match = matches[index] || null;
        const fileId = match && typeof match === 'object' ? match.fileId : match;
        const version = match && typeof match === 'object' ? match.version : 'legacy';
        if (!fileId) {
          finishJob(job, '', Boolean(match && match.error));
          return;
        }
        job.fileId = fileId;
        job.storageKey = String(fileId) + ':' + String(version || 'current');
        remoteJobs.push(job);
      });
      let nextRemoteJob = 0;
      const workerCount = Math.min(4, remoteJobs.length);
      async function worker() {
        while (nextRemoteJob < remoteJobs.length && !printWindow.closed) {
          const job = remoteJobs[nextRemoteJob];
          nextRemoteJob += 1;
          const result = await loadStudentPrintPhoto(job.fileId, 0);
          finishJob(job, result.photoData, result.failed);
        }
      }
      await Promise.all(Array.from({
        length: workerCount
      }, function () {
        return worker();
      }));
    }
    if (!printWindow.closed) {
      CardDesignRuntime.printCards(batchContainer, {
        printWindow: printWindow,
        title: 'Student ID Cards'
      });
    }
  } catch (error) {
    pendingJobs.forEach(function (job) {
      if (!job.finished) finishJob(job, '', true);
    });
    if (!printWindow.closed) {
      CardDesignRuntime.printCards(batchContainer, {
        printWindow: printWindow,
        title: 'Student ID Cards'
      });
    }
  } finally {
    button.disabled = false;
  }
}

</script>
<style>
#setupDesignButton {
  white-space: normal;
  overflow-wrap: anywhere;
  height: auto;
  line-height: 1.4;
}
.studio-sync-status {
  margin: 8px 0;
  color: #475467;
  font-size: 12px;
}
</style>
<script>
// Refresh saved sheet values on returning to this studio; never reload the page.
(function () {
  let timer = null;
  let busy = false;
  let lastStarted = 0;
  let hasLeft = false;
  function recordKey(r) {
    return String(r.recordKey || '');
  }
  function status(message, failed) {
    let node = document.getElementById('studioSyncStatus');
    if (!node) {
      node = document.createElement('p');
      node.id = 'studioSyncStatus';
      node.className = 'studio-sync-status';
      node.setAttribute('role', 'status');
      document.getElementById('cardsWrapper').parentNode.prepend(node);
    }
    node.textContent = message;
    node.style.color = failed ? '#b42318' : '#475467';
  }
  function schedule() {
    if (!hasLeft || document.hidden) return;
    clearTimeout(timer);
    timer = setTimeout(refresh, 900);
  }
  function refresh() {
    if (document.hidden || busy || !initialConfiguration.hasSpreadsheet) return;
    if (Date.now() - lastStarted < 2000) return;
    // Leave unfinished edits alone; apply fresh records after the dialog closes.
    if (Array.from(document.querySelectorAll('.modal')).some(function (el) {
      return !el.hidden && getComputedStyle(el).display !== 'none';
    })) {
      timer = setTimeout(refresh, 1500);
      return;
    }
    hasLeft = false;
    busy = true;
    lastStarted = Date.now();
    status('Checking for spreadsheet changes…', false);
    google.script.run.withSuccessHandler(function (data) {
      busy = false;
      if (!Array.isArray(data)) {
        status('Could not read spreadsheet updates.', true);
        return;
      }
      if (JSON.stringify(data) === JSON.stringify(recordsList)) {
        status('Spreadsheet checked. No data changes found.', false);
        return;
      }
      const select = document.getElementById('recordSelect');
      const previous = select.value !== '' ? recordsList[select.value] : null;
      const showingAll = document.getElementById('cardsWrapper').classList.contains('previewing-all');
      const priorNameSearch = window.activeNameSearch;
      let match = previous ? data.find(function (r) {
        return recordKey(r) === recordKey(previous);
      }) : null;
      if (!match && previous) {
        const sameName = data.filter(function (r) {
          return studentMappedFullName(r) === studentMappedFullName(previous);
        });
        if (sameName.length === 1) match = sameName[0];
      }
      populateRecordsDropdown(data, match ? recordKey(match) : '');
      if (priorNameSearch) {
        const input = document.getElementById('studentNameSearchInput');
        input.value = priorNameSearch;
        searchStudentByFullName();
      } else if (showingAll && data.length) previewAllStudentCards();
      status(previous && !match && !showingAll ? 'Spreadsheet updated. Please select the record again; its identifying details changed or it was removed.' : 'Spreadsheet data reloaded. Any displayed card uses the updated values.', false);
    }).withFailureHandler(function (error) {
      busy = false;
      hasLeft = true;
      status('Unable to update spreadsheet data: ' + (error.message || String(error)) + '. Switch back to this tab to retry.', true);
    }).getStudentData();
  }
  window.addEventListener('blur', function () {
    hasLeft = true;
  });
  window.addEventListener('focus', schedule);
  // Also works when the Apps Script iframe itself does not receive window focus.
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) hasLeft = true;else schedule();
  });
  document.addEventListener('pointerdown', schedule);
})();
</script>
<?!= include('ReliabilityClient'); ?>
<style>#studentPrintListPanel::backdrop {background:rgba(23,32,51,.45)}</style>
<script>
window.addEventListener('DOMContentLoaded', function () {
  // Run after the shared toolbar has grouped the existing print buttons.
  const group = document.querySelector('.preview-toolbar .studio-print-actions');
  const button = document.getElementById('openStudentPrintListButton');
  if (group && button) group.appendChild(button);
});
</script>
</body>
</html>
`;

    case 'StudioTabBridge':
      return `<script>
(function () {
  'use strict';
  // These studio documents are created only by the authenticated parent page.
  const host = window.parent;
  if (host === window || !host.IDStudioTabs) throw new Error('Open this studio from ID Card Studio.');
  const bridge = host.IDStudioTabs.connect(window);
  if (!bridge) throw new Error('Unknown studio frame.');
  window.google = host.google;
  window.STUDIO_FRAME_ORIGIN = host.location.origin;
  window.StudioTabsBridge = bridge;

  document.addEventListener('click', function (event) {
    const anchor = event.target.closest && event.target.closest('a[href]');
    if (!anchor || !window.STUDIO_URL || anchor.hasAttribute('download')) return;
    let url, app;
    try { url = new URL(anchor.href, window.STUDIO_URL); app = new URL(window.STUDIO_URL); }
    catch (error) { return; }
    if (url.origin !== app.origin || url.pathname !== app.pathname) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    const studio = url.searchParams.get('studio') || url.searchParams.get('page') || '';
    const screen = url.searchParams.get('screen') || '';
    if (studio === 'control-center' || screen === 'control-center') bridge.select('control-center');
    else if (studio === 'student' || screen === 'student-studio') bridge.select('student');
    else if (studio === 'staff' || screen === 'staff-studio') bridge.select('staff');
    else if (studio === 'custom' || screen === 'custom-studio') bridge.select('custom');
    else if (studio === 'design' || screen === 'card-designer-v3' || screen === 'design-studio') bridge.select('design');
    else bridge.focusTabs();
  }, true);

  window.addEventListener('DOMContentLoaded', function () {
    // Hide redundant home controls: all studios are now available above the page.
    document.querySelectorAll('a[href]').forEach(function (anchor) {
      if (!/^(?:←\\s*)?ID Card Studio$/i.test(anchor.textContent.trim())) return;
      try {
        const url = new URL(anchor.href, window.STUDIO_URL);
        const app = new URL(window.STUDIO_URL);
        if (url.origin === app.origin && url.pathname === app.pathname && !url.search) anchor.hidden = true;
      } catch (error) {}
    });
    bridge.ready();
  });
})();
</script>
`;

    case 'StudioTabs':
      return `<!doctype html>
<html>
<head>
  <base target="_top">
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ID Card Studio</title>
  <style>
    * {box-sizing:border-box}
    html,body {height:100%;margin:0}
    body {font:14px 'Segoe UI',Arial,sans-serif;color:#172033;background:#e9eef5;display:flex;flex-direction:column}
    .app-header {flex:none;background:#f7f9fc;border-bottom:1px solid #cbd5e1;padding:14px 22px 0}
    .heading {display:flex;align-items:center;gap:12px;margin-bottom:12px}
    .mark {background:#185adb;color:#fff;border-radius:10px;display:grid;place-items:center;width:38px;height:38px;font-size:23px}
    h1 {font-size:22px;margin:0}.hint {font-size:12px;color:#667085;margin:3px 0 0}
    .tabs {display:flex;gap:6px;overflow-x:auto;padding-bottom:0}
    .tabs button {flex:0 0 auto;display:flex;align-items:center;gap:8px;min-height:44px;padding:10px 18px;border:1px solid transparent;border-bottom:3px solid transparent;border-radius:8px 8px 0 0;background:transparent;color:#475467;font:600 14px 'Segoe UI',Arial,sans-serif;cursor:pointer}
    .tabs button:hover {background:#e8eef7}
    .tabs button[aria-selected=true] {background:#e7effd;color:#174ea6;border-color:#c6d5ef;border-bottom-color:#185adb}
    button:focus-visible {outline:2px solid #185adb;outline-offset:-3px}
    .tabs svg {width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
    #workspaces {position:relative;flex:1;min-height:0}
    .workspace {position:absolute;inset:0;visibility:hidden;pointer-events:none}
    .workspace.active {visibility:visible;pointer-events:auto}
    iframe {display:block;border:0;width:100%;height:100%;background:#eef2f7}
    .load-state {position:absolute;inset:0;display:grid;place-content:center;text-align:center;gap:12px;padding:30px;background:#eef2f7;z-index:1}
    .load-state p {max-width:520px;margin:0;line-height:1.5}
    .load-state button {justify-self:center;padding:9px 16px;border:1px solid #b4c3d8;border-radius:7px;background:#fff;color:#172033;cursor:pointer}
    [hidden] {display:none!important}
    #accessMessage {margin:0;padding:10px 22px;background:#fff0dd;font-size:13px}
    @media(max-width:600px) {.app-header {padding:10px 10px 0}h1 {font-size:20px}.tabs button {padding:10px 12px}.hint {max-width:300px}}
  </style>
</head>
<body>
  <header class="app-header">
    <div class="heading"><span class="mark" aria-hidden="true">▣</span><div><h1>ID Card Studio</h1><p class="hint">Switch studios using the tabs. Your open work stays in place.</p></div></div>
    <nav class="tabs" role="tablist" aria-label="ID card studios" id="studioTabs">
      <button id="tab-student" role="tab" type="button" data-studio="student" aria-controls="panel-student" aria-selected="false" tabindex="-1"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m2 8 10-5 10 5-10 5Z M6 10v5q6 5 12 0v-5 M22 8v8"/></svg>Student</button>
      <button id="tab-staff" role="tab" type="button" data-studio="staff" aria-controls="panel-staff" aria-selected="false" tabindex="-1"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="7" r="4"/><path d="M4 22v-3a8 8 0 0 1 16 0v3 M9 15l3 4 3-4"/></svg>Staff</button>
      <button id="tab-custom" role="tab" type="button" data-studio="custom" aria-controls="panel-custom" aria-selected="false" tabindex="-1"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="2" y="4" width="20" height="16" rx="3"/><circle cx="8" cy="10" r="2"/><path d="M4 17q4-6 8 0 M15 9h4 M15 13h4"/></svg>Custom</button>
      <button id="tab-design" role="tab" type="button" data-studio="design" aria-controls="panel-design" aria-selected="false" tabindex="-1"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m4 16 12-12 4 4L8 20H4Z M13 7l4 4"/></svg>Design Studio</button>
      <? if (isAdministrator === true) { ?>
      <button id="tab-control-center" role="tab" type="button" data-studio="control-center" aria-controls="panel-control-center" aria-selected="false" tabindex="-1"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 2 8 4v6c0 5-8 10-8 10S4 17 4 12V6Z m-4 10 3 3 5-6"/></svg>Control Center</button>
      <? } ?>
    </nav>
  </header>
  <p id="accessMessage" role="status" hidden></p>
  <main id="workspaces" aria-label="Studio workspace"></main>
<script>
(function () {
  'use strict';
  const initialTab = <?!= JSON.stringify(initialTab) ?>;
  const panels = new Map();
  const tabBar = document.getElementById('studioTabs');
  const workspace = document.getElementById('workspaces');
  let active = '';
  let checkingAccess = false;
  function buttonFor(type) { return document.getElementById('tab-' + type); }
  function call(name, ...args) {
    return new Promise((resolve, reject) => google.script.run.withSuccessHandler(resolve).withFailureHandler(reject)[name](...args));
  }
  function panelFor(type) {
    if (panels.has(type)) return panels.get(type);
    const panel = document.createElement('section');
    panel.id = 'panel-' + type; panel.className = 'workspace'; panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', 'tab-' + type);
    const state = document.createElement('div'); state.className = 'load-state';
    const text = document.createElement('p'); text.setAttribute('role', 'status');
    const retry = document.createElement('button'); retry.type = 'button'; retry.textContent = 'Try Again'; retry.hidden = true;
    state.append(text, retry); panel.appendChild(state); workspace.appendChild(panel);
    const entry = {type, panel, state, text, retry, frame: null, loading: false, generation: 0};
    panels.set(type, entry); retry.onclick = () => load(entry);
    return entry;
  }
  function fail(entry, text) {
    entry.loading = false; entry.text.textContent = text; entry.retry.hidden = false; entry.state.hidden = false;
  }
  async function load(entry) {
    if (entry.loading) return;
    entry.loading = true; entry.state.hidden = false; entry.retry.hidden = true;
    entry.text.textContent = 'Opening ' + buttonFor(entry.type).textContent.trim() + '…';
    const generation = ++entry.generation;
    try {
      const result = await call('getStudioTabHtml', entry.type);
      if (entry.generation !== generation || !buttonFor(entry.type)) return;
      if (!result || result.studio !== entry.type || typeof result.html !== 'string') throw new Error('The studio could not be loaded.');
      if (entry.frame) entry.frame.remove();
      const frame = document.createElement('iframe');
      frame.title = buttonFor(entry.type).textContent.trim();
      frame.allow = 'camera; microphone; clipboard-write';
      entry.frame = frame;
      // srcdoc inherits this authenticated page's origin and sandbox. The bridge
      // shares its Apps Script transport; credentials never appear in the HTML.
      frame.srcdoc = result.html;
      entry.panel.appendChild(frame);
      setTimeout(() => {
        if (entry.loading && entry.generation === generation) fail(entry, 'This studio is taking longer to open. You can try again.');
      }, 30000);
    } catch (error) {
      if (entry.generation === generation) fail(entry, 'Unable to open this studio: ' + (error.message || String(error)));
    }
  }
  function focusTabs() { const button = buttonFor(active); if (button) button.focus(); }
  function select(type, focus) {
    const button = buttonFor(type);
    if (!button || button.hidden) return;
    const previous = panels.get(active);
    if (previous && previous.frame && active !== type) {
      previous.frame.contentWindow.dispatchEvent(new previous.frame.contentWindow.Event('blur'));
    }
    active = type;
    const entry = panelFor(type);
    tabBar.querySelectorAll('[role=tab]').forEach(tab => {
      const current = tab.dataset.studio === type;
      tab.setAttribute('aria-selected', String(current)); tab.tabIndex = current ? 0 : -1;
    });
    panels.forEach(item => {
      const current = item.type === type;
      item.panel.classList.toggle('active', current);
      item.panel.setAttribute('aria-hidden', String(!current));
      item.panel.inert = !current;
    });
    if (!entry.frame && !entry.loading) load(entry);
    else if (entry.frame && !entry.loading) {
      const child = entry.frame.contentWindow;
      child.dispatchEvent(new child.Event('resize'));
      child.dispatchEvent(new child.Event('focus'));
    }
    if (focus) button.focus();
  }
  function hasUnsaved(entry) {
    if (!entry.frame) return false;
    try {
      const child = entry.frame.contentWindow;
      const event = new child.Event('beforeunload', {cancelable: true});
      return !child.dispatchEvent(event);
    } catch (error) { return false; }
  }
  function reload(entry) {
    if (hasUnsaved(entry) && !confirm('This studio has unsaved changes. Reload it anyway?')) return;
    entry.loading = false;
    load(entry);
  }
  async function refreshAccess() {
    if (checkingAccess) return;
    checkingAccess = true;
    try {
      const access = await call('getStudioTabsAccess');
      const button = buttonFor('control-center');
      if (!access.isAdministrator && button) {
        const entry = panels.get('control-center');
        if (entry) { entry.generation++; entry.panel.remove(); panels.delete('control-center'); }
        button.remove();
        if (active === 'control-center') select('student', true);
      }
    } catch (error) {
      const note = document.getElementById('accessMessage');
      note.textContent = 'Unable to verify access: ' + (error.message || String(error)); note.hidden = false;
    } finally { checkingAccess = false; }
  }
  window.IDStudioTabs = Object.freeze({
    connect(child) {
      const entry = Array.from(panels.values()).find(item => item.frame && item.frame.contentWindow === child);
      if (!entry) return null;
      const generation = entry.generation;
      return Object.freeze({
        select: type => select(type, true), focusTabs,
        reload: () => { if (entry.frame && entry.frame.contentWindow === child) reload(entry); }, refreshAccess,
        ready() {
          if (entry.generation !== generation || !entry.frame || entry.frame.contentWindow !== child) return;
          entry.loading = false; entry.state.hidden = true;
          if (active === entry.type) child.dispatchEvent(new child.Event('resize'));
        }
      });
    }
  });
  tabBar.addEventListener('click', event => {
    const button = event.target.closest('[role=tab]');
    if (button) { select(button.dataset.studio, true); refreshAccess(); }
  });
  tabBar.addEventListener('keydown', event => {
    const tabs = Array.from(tabBar.querySelectorAll('[role=tab]'));
    let index = tabs.indexOf(document.activeElement);
    if (index < 0) return;
    if (event.key === 'ArrowRight') index = (index + 1) % tabs.length;
    else if (event.key === 'ArrowLeft') index = (index + tabs.length - 1) % tabs.length;
    else if (event.key === 'Home') index = 0;
    else if (event.key === 'End') index = tabs.length - 1;
    else return;
    event.preventDefault(); select(tabs[index].dataset.studio, true); refreshAccess();
  });
  window.addEventListener('beforeunload', event => {
    if (Array.from(panels.values()).some(hasUnsaved)) { event.preventDefault(); event.returnValue = ''; }
  });
  select(buttonFor(initialTab) ? initialTab : 'student', false);
})();
</script>
</body>
</html>
`;

    default:
      throw new Error('Unknown embedded template.');
  }
}
