// Write guard: a Windows process may change files only under the allowed folders. Frida 17.
//
//   rea-suite frida common/frida/write-guard.js --config-json '{"allow": ["D:\\work\\run"]}' \
//     --spawn D:\work\run\Game.exe
//
// For running an original game (or a port's copy of it) without letting it write into its
// install folder, the user's profile or anywhere else: every open for writing, delete-on-close,
// rename and hard link goes through a path check at the native API (ntdll), below every
// library the game might use.
//
// Config (rpc configure):
//   { "allow": ["D:\\work\\run"],            // folders (and everything below) writes may go to
//     "allow_devices": ["^\\\\Device\\\\NamedPipe"],   // regexes for kernel objects that are no
//                                            // disk files (default: pipes, sockets, console, HID, GPU)
//     "deny_children": true }                // refuse to start child processes (launchers, crash reporters)
//
// - NtCreateFile and NtOpenFile with write, delete or attribute access, a disposition other than
//   FILE_OPEN, or FILE_DELETE_ON_CLOSE are refused (STATUS_ACCESS_DENIED) unless the path is
//   allowed. The path is resolved through the kernel (GetFinalPathNameByHandleW on the nearest
//   existing ancestor), so a junction or symlink inside an allowed folder cannot reach outside it.
// - NtSetInformationFile renames (classes 10, 56, 65, 66) are checked by their destination; hard
//   links (11, 57, 72, 73) are refused, since one could alias an original file under an allowed
//   folder. A CModule filters the classes in C, so Frida's own I/O never reenters JavaScript.
// - NtCreateUserProcess is refused when deny_children is on (the default).
// Messages: ready, write-denied, rename-check, hardlink-denied, child-process-denied, guard-error.
// Windows only; checked on x64.
'use strict';

const keep = [];
let roots = null;
let devices = [];
const DEFAULT_DEVICES = [
  '^\\\\Device\\\\(NamedPipe|Afd|Nsi|ConDrv|KsecDD|DxgKrnl|Video)',
  '^\\\\\\?\\?\\\\pipe\\\\',
  '^\\\\\\?\\?\\\\hid#',
];
const STATUS_ACCESS_DENIED = -1073741790;

function api(module, name, result, args) {
  const address = Process.getModuleByName(module).getExportByName(name);
  return { address, call: new NativeFunction(address, result, args) };
}

function replace(target, result, args, callback) {
  const replacement = new NativeCallback(callback, result, args);
  keep.push(replacement);
  Interceptor.replace(target.address, replacement);
}

function plain(path) {
  return path.replace(/^\\\\\?\\/, '').replace(/\\+$/, '').toLowerCase();
}

function within(path) {
  const value = plain(path);
  return roots.some(root => value === root || value.startsWith(root + '\\'));
}

function objectName(attributes) {
  if (attributes.isNull()) return null;
  const name = attributes.add(Process.pointerSize * 2).readPointer();
  if (name.isNull()) return null;
  const length = name.readU16();
  return name.add(Process.pointerSize).readPointer().readUtf16String(length / 2);
}

// A UNICODE_STRING as the native API takes it; the caller holds `text` while `pointer` is used.
function unicodeString(value) {
  const text = Memory.allocUtf16String(value);
  const pointer = Memory.alloc(Process.pointerSize * 2);
  pointer.writeU16(value.length * 2);
  pointer.add(2).writeU16(value.length * 2 + 2);
  pointer.add(Process.pointerSize).writePointer(text);
  return { pointer, text };
}

function guard() {
  const ps = Process.pointerSize;
  const attributesSize = ps === 8 ? 48 : 24;
  const close = api('kernel32.dll', 'CloseHandle', 'int', ['pointer']).call;
  const finalPath = api('kernel32.dll', 'GetFinalPathNameByHandleW', 'uint', ['pointer', 'pointer', 'uint', 'uint']).call;
  const fullPath = api('kernel32.dll', 'GetFullPathNameW', 'uint', ['pointer', 'uint', 'pointer', 'pointer']).call;
  const openArgs = ['pointer', 'uint', 'pointer', 'pointer', 'uint', 'uint'];
  const open = api('ntdll.dll', 'NtOpenFile', 'int', openArgs);
  const ntOpen = open.call; // stays the original's trampoline once replaced

  function handlePath(handle) {
    const buffer = Memory.alloc(65536);
    const size = finalPath(handle, buffer, 32768, 0);
    return size > 0 && size < 32768 ? buffer.readUtf16String(size) : null;
  }

  // The full path of name, resolved through the kernel at its nearest existing ancestor.
  function resolve(attributes, name) {
    const directory = attributes.add(ps).readPointer();
    let pending = name;
    let suffix = '';
    for (let depth = 0; depth < 128; depth++) {
      const copy = Memory.alloc(attributesSize);
      Memory.copy(copy, attributes, attributesSize);
      const unicode = unicodeString(pending);
      copy.add(ps * 2).writePointer(unicode.pointer);
      const handle = Memory.alloc(ps);
      handle.writePointer(NULL);
      const io = Memory.alloc(ps * 2);
      let resolved = null;
      if (pending.length === 0 && !directory.isNull()) {
        resolved = handlePath(directory);
      } else if (ntOpen(handle, 0x80, copy, io, 7, 0) >= 0) { // FILE_READ_ATTRIBUTES, share all
        const opened = handle.readPointer();
        try { resolved = handlePath(opened); } finally { close(opened); }
      }
      if (resolved !== null) {
        const buffer = Memory.alloc(65536);
        const size = fullPath(Memory.allocUtf16String(resolved + suffix), 32768, buffer, NULL);
        return size > 0 && size < 32768 ? buffer.readUtf16String(size) : null;
      }
      const slash = pending.lastIndexOf('\\');
      if (slash < 0) {
        if (directory.isNull() || pending.length === 0) return null;
        suffix = '\\' + pending + suffix;
        pending = '';
      } else {
        suffix = pending.substring(slash) + suffix;
        pending = pending.substring(0, slash);
      }
    }
    return null;
  }

  function allowed(attributes) {
    try {
      const name = objectName(attributes);
      if (name === null) return false;
      if (devices.some(pattern => pattern.test(name))) return true;
      const resolved = resolve(attributes, name);
      if (resolved !== null && within(resolved)) return true;
      send({ kind: 'write-denied', path: name, resolved });
    } catch (error) {
      send({ kind: 'guard-error', error: String(error) });
    }
    return false;
  }

  // GENERIC_WRITE, GENERIC_ALL, DELETE, WRITE_DAC, WRITE_OWNER, FILE_WRITE_DATA,
  // FILE_APPEND_DATA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES
  const writeMask = 0x40000000 | 0x10000000 | 0x10000 | 0x40000 | 0x80000 | 2 | 4 | 0x10 | 0x100;
  const deleteOnClose = 0x1000;
  function denied(output, io) {
    if (!output.isNull()) output.writePointer(NULL);
    if (!io.isNull()) { io.writeS32(STATUS_ACCESS_DENIED); io.add(ps).writePointer(NULL); }
    return STATUS_ACCESS_DENIED;
  }
  const createArgs = ['pointer', 'uint', 'pointer', 'pointer', 'pointer', 'uint', 'uint', 'uint', 'uint', 'pointer', 'uint'];
  const create = api('ntdll.dll', 'NtCreateFile', 'int', createArgs);
  replace(create, 'int', createArgs, (...args) => {
    const mutation = (args[1] & writeMask) !== 0 || args[7] !== 1 || (args[8] & deleteOnClose) !== 0;
    if (mutation && !allowed(args[2])) return denied(args[0], args[3]);
    return create.call(...args);
  });
  replace(open, 'int', openArgs, (...args) => {
    const mutation = (args[1] & writeMask) !== 0 || (args[5] & deleteOnClose) !== 0;
    if (mutation && !allowed(args[2])) return denied(args[0], args[3]);
    return open.call(...args);
  });

  const setArgs = ['pointer', 'pointer', 'pointer', 'uint', 'uint'];
  const set = api('ntdll.dll', 'NtSetInformationFile', 'int', setArgs);
  let originalSet;
  const nameOffset = ps === 8 ? 20 : 12; // FILE_RENAME_INFORMATION: FileNameLength, then FileName
  const checkSet = new NativeCallback((file, io, information, size, kind) => {
    if ([11, 57, 72, 73].includes(kind)) {
      send({ kind: 'hardlink-denied' });
      return denied(NULL, io);
    }
    if (size < nameOffset) return denied(NULL, io);
    const bytes = information.add(nameOffset - 4).readU32();
    if (bytes > size - nameOffset || (bytes & 1) !== 0 || bytes > 65532) return denied(NULL, io);
    const directory = information.add(ps).readPointer();
    let name = information.add(nameOffset).readUtf16String(bytes / 2);
    send({ kind: 'rename-check', information_class: kind, target: name });
    // A bare name renames within the source's folder. Querying the source can wait on its
    // outstanding asynchronous I/O, so full and directory-relative names skip that query.
    if (directory.isNull() && !name.startsWith('\\') && !/^[a-z]:/i.test(name)) {
      const source = handlePath(file);
      if (source === null || !within(source)) return denied(NULL, io);
      name = source.substring(0, source.lastIndexOf('\\') + 1) + name;
    }
    if (name.startsWith('\\\\?\\')) name = '\\??\\' + name.substring(4);
    else if (/^[a-z]:\\/i.test(name)) name = '\\??\\' + name;
    else if (name.startsWith('\\\\')) name = '\\??\\UNC\\' + name.substring(2);
    const attributes = Memory.alloc(attributesSize);
    attributes.writeByteArray(new Uint8Array(attributesSize));
    attributes.writeU32(attributesSize);
    attributes.add(ps).writePointer(directory);
    const unicode = unicodeString(name);
    attributes.add(ps * 2).writePointer(unicode.pointer);
    attributes.add(ps * 3).writeU32(0x40); // OBJ_CASE_INSENSITIVE
    if (!allowed(attributes)) return denied(NULL, io);
    return originalSet(file, io, information, size, kind);
  }, 'int', setArgs);
  const originalStorage = Memory.alloc(ps);
  originalStorage.writePointer(NULL);
  const filter = new CModule(`
    typedef int (*set_fn)(void *, void *, void *, unsigned int, unsigned int);
    extern void * original_set;
    extern int check_set(void *, void *, void *, unsigned int, unsigned int);
    int filter_set(void *f, void *io, void *info, unsigned int size, unsigned int kind) {
      switch (kind) {
        case 10: case 11: case 56: case 57: case 65: case 66: case 72: case 73:
          return check_set(f, io, info, size, kind);
        default:
          return ((set_fn) original_set)(f, io, info, size, kind);
      }
    }
  `, { original_set: originalStorage, check_set: checkSet });
  const originalAddress = Interceptor.replaceFast(set.address, filter.filter_set);
  originalStorage.writePointer(originalAddress);
  originalSet = new NativeFunction(originalAddress, 'int', setArgs);
  keep.push(checkSet, filter, originalStorage);
}

function denyChildren() {
  const args = ['pointer', 'pointer', 'uint', 'uint', 'pointer', 'pointer', 'uint', 'uint', 'pointer', 'pointer', 'pointer'];
  const child = api('ntdll.dll', 'NtCreateUserProcess', 'int', args);
  replace(child, 'int', args, (process, thread) => {
    process.writePointer(NULL);
    thread.writePointer(NULL);
    send({ kind: 'child-process-denied' });
    return STATUS_ACCESS_DENIED;
  });
}

rpc.exports = {
  configure(config) {
    if (roots !== null) throw new Error('already configured');
    if (Process.platform !== 'windows') throw new Error('the write guard is for Windows');
    if (!Array.isArray(config.allow) || config.allow.length === 0) throw new Error('give "allow": [folders]');
    roots = config.allow.map(plain);
    if (roots.some(root => !/^[a-z]:\\|^\\\\/.test(root) || /^[a-z]:$/.test(root)))
      throw new Error('allowed folders are full paths, not drive roots');
    devices = (config.allow_devices || DEFAULT_DEVICES).map(pattern => new RegExp(pattern, 'i'));
    guard();
    if (config.deny_children !== false) denyChildren();
    Interceptor.flush();
    send({ kind: 'ready', allow: config.allow, deny_children: config.deny_children !== false });
    return true;
  }
};
