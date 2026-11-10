// Passive observer: logs calls of chosen functions without changing them. Frida 17.
//
//   rea-suite frida common/frida/observer.js --config common/frida/examples/xinput.json --spawn game.exe
//
// The config (rpc configure) names the targets; nothing about a game lives here:
//   { "interval_ms": 2000,                   // count and rate reports (0: none)
//     "targets": [ {
//       "name": "XInputGetState",            // label in every message
//       "export": "xinput1_4.dll!XInputGetState",   // or a list of alternatives, each hooked when it loads
//       "rva": "0x4a8f20", "module": "Game.exe",    // or: an address in a module (default: the main one)
//       "iat": "0x6c2010",                   // or: the function an IAT slot of the module points to
//       "mode": "change",                    // call: every call; change: when `key` changes; count: totals per caller
//       "at": "leave",                       // emit on enter or leave (leave has the result)
//       "args": 2,                           // log arg0..arg1 as pointers
//       "reads": [ { "as": "buttons", "from": "arg1", "offset": 4, "type": "u16" } ],
//       "key": ["index", "result", "buttons"],  // change: the values compared (default: all)
//       "group": "index",                    // change: compared per value of this one (per pad)
//       "caller": true,                      // the return address as module+offset
//       "only_from": "Game.exe",             // count and log only calls returning into this module
//       "format": "pad {index}: {buttons}",  // a text line from the values
//       "limit": 10000 } ] }                 // most messages for this target
// A read: "from" is argN or result; without "offset" the value itself, with it memory at
// pointer+offset; "type" u8 u16 u32 u64 s8 s16 s32 s64 float double pointer utf8 utf16 ansi,
// bytes:N, or array with "count" (a number or argN), "stride" (a number or {"x64": 16,
// "ia32": 12}) and "fields" (reads with offsets into each element).
// Messages: attached, pending, call, count, rate, limit, error; `ms` is the time in the process.
// Counts are reported every interval_ms, so a count target needs one.
'use strict';

const targets = [];
let interval = null;

function now() { return Date.now(); }

function moduleOf(name) {
  return name ? Process.findModuleByName(name) : Process.mainModule;
}

function where(address) {
  const module = Process.findModuleByAddress(address);
  return module === null ? address.toString() : `${module.name}+0x${address.sub(module.base).toString(16)}`;
}

function numberOf(value, x) {
  if (typeof value === 'number') return value;
  if (typeof value === 'string' && /^arg\d+$/.test(value)) return x.args[parseInt(value.slice(3))].toUInt32();
  if (value !== null && typeof value === 'object') return value[Process.arch];
  return parseInt(value);
}

function readAt(p, type) {
  if (type.startsWith('bytes:')) {
    const size = parseInt(type.slice(6));
    return Array.from(new Uint8Array(p.readByteArray(size)), b => b.toString(16).padStart(2, '0')).join('');
  }
  switch (type) {
    case 'u8': return p.readU8();
    case 'u16': return p.readU16();
    case 'u32': return p.readU32();
    case 'u64': return p.readU64().toString();
    case 's8': return p.readS8();
    case 's16': return p.readS16();
    case 's32': return p.readS32();
    case 's64': return p.readS64().toString();
    case 'float': return p.readFloat();
    case 'double': return p.readDouble();
    case 'pointer': return p.readPointer().toString();
    case 'utf8': return p.readUtf8String();
    case 'utf16': return p.readUtf16String();
    case 'ansi': return Process.platform === 'windows' ? p.readAnsiString() : p.readUtf8String();
    default: throw new Error(`unknown type ${type}`);
  }
}

// The value itself, for a read without an offset.
function valueOf(v, type) {
  switch (type) {
    case 'u8': return v.toUInt32() & 0xff;
    case 'u16': return v.toUInt32() & 0xffff;
    case 'u32': return v.toUInt32();
    case 's32': return v.toInt32();
    case 'u64': return uint64(v.toString()).toString();
    case 'pointer': return v.toString();
    case 'utf8': return v.isNull() ? null : v.readUtf8String();
    case 'utf16': return v.isNull() ? null : v.readUtf16String();
    case 'ansi': return v.isNull() ? null : readAt(v, 'ansi');
    default: throw new Error(`type ${type} needs an offset`);
  }
}

function read(spec, x) {
  const source = spec.from === 'result' ? x.result : x.args[parseInt(spec.from.slice(3))];
  try {
    if (spec.type === 'array') {
      const count = Math.min(numberOf(spec.count, x), spec.max || 64);
      const stride = numberOf(spec.stride, x);
      const items = [];
      for (let i = 0; i < count; i++) {
        const element = {};
        for (const field of spec.fields) element[field.as] = readAt(source.add(i * stride + (field.offset || 0)), field.type);
        items.push(element);
      }
      return items;
    }
    if (spec.offset === undefined) return valueOf(source, spec.type);
    return readAt(source.add(spec.offset), spec.type);
  } catch (e) {
    return null;
  }
}

function format(template, values) {
  return template.replace(/\{(\w+)\}/g, (_, key) => {
    const value = values[key];
    return typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value);
  });
}

function phase(spec, t) {
  return spec.at || (spec.from === 'result' ? 'leave' : t.at);
}

// Reads of one phase: enter (arguments as they come in) or leave (the result, out-parameters).
function reads(t, x, when) {
  const values = {};
  for (const spec of t.spec.reads || []) if (phase(spec, t) === when) values[spec.as] = read(spec, x);
  return values;
}

function emit(t, x, values) {
  for (let i = 0; i < (t.spec.args || 0); i++) values[`arg${i}`] = x.args[i].toString();
  if (x.result !== undefined && values.result === undefined) values.result = x.result.toString();
  if (t.spec.caller) values.caller = where(x.returnAddress);
  if (t.spec.mode === 'change') {
    const key = JSON.stringify((t.spec.key || Object.keys(values)).map(k => values[k]));
    const group = t.spec.group === undefined ? '' : String(values[t.spec.group]);
    if (t.last[group] === key) return;
    t.last[group] = key;
  }
  if (t.sent >= t.limit) {
    if (t.sent++ === t.limit) send({ kind: 'limit', target: t.spec.name, ms: now(), limit: t.limit });
    return;
  }
  t.sent++;
  const message = { kind: 'call', target: t.spec.name, ms: now(), ...values };
  if (t.spec.format) message.text = format(t.spec.format, { name: t.spec.name, ...values });
  send(message);
}

function argument(value) {
  return typeof value === 'string' && /^arg\d+$/.test(value) ? parseInt(value.slice(3)) + 1 : 0;
}

function hook(t, address, label) {
  const only = t.spec.only_from ? Process.findModuleByName(t.spec.only_from) : null;
  const wanted = r => only === null || (r.compare(only.base) >= 0 && r.compare(only.base.add(only.size)) < 0);
  const used = (t.spec.reads || []).flatMap(r => [argument(r.from), argument(r.count), argument(r.stride)]);
  const argCount = Math.max(t.spec.args || 0, ...used);
  Interceptor.attach(address, {
    onEnter(args) {
      this.skip = !wanted(this.returnAddress);
      if (this.skip) return;
      t.total++;
      if (t.spec.mode === 'count') {
        const caller = where(this.returnAddress);
        t.callers[caller] = (t.callers[caller] || 0) + 1;
        return;
      }
      this.x = { args: Array.from({ length: argCount }, (_, i) => args[i]), returnAddress: this.returnAddress };
      this.values = reads(t, this.x, 'enter');
      if (t.at === 'enter') emit(t, this.x, this.values);
    },
    onLeave(result) {
      if (this.skip || t.spec.mode === 'count' || t.at !== 'leave') return;
      const x = { ...this.x, result };
      emit(t, x, { ...this.values, ...reads(t, x, 'leave') });
    }
  });
  send({ kind: 'attached', target: t.spec.name, via: label, address: address.toString(), at: where(address), ms: now() });
}

// Resolve what can be resolved now; the rest waits for its module (or a bound IAT slot).
function resolve() {
  for (const t of targets) {
    for (const want of t.wants) {
      if (want.done) continue;
      // a caller filter needs its module loaded first
      if (t.spec.only_from && Process.findModuleByName(t.spec.only_from) === null) continue;
      let address = null;
      if (want.export) {
        const [module, name] = want.export.split('!');
        const found = Process.findModuleByName(module);
        if (found !== null) {
          address = found.findExportByName(name);
          if (address === null) { want.done = true; send({ kind: 'error', target: t.spec.name, error: `no export ${want.export}` }); continue; }
        }
      } else {
        const module = moduleOf(t.spec.module);
        if (module === null) continue;
        if (want.rva !== undefined) address = module.base.add(ptr(want.rva));
        else {
          const value = module.base.add(ptr(want.iat)).readPointer();
          // Before the loader binds the slot it holds an RVA; wait for a pointer into a module.
          if (Process.findModuleByAddress(value) !== null) address = value;
        }
      }
      if (address === null) continue;
      want.done = true;
      try {
        hook(t, address, want.export || (want.rva !== undefined ? `rva ${want.rva}` : `iat ${want.iat}`));
      } catch (e) {
        send({ kind: 'error', target: t.spec.name, error: String(e) });
      }
    }
  }
}

function report() {
  const counts = {};
  for (const t of targets) {
    counts[t.spec.name] = t.total;
    if (t.spec.mode === 'count') send({ kind: 'count', target: t.spec.name, ms: now(), total: t.total, callers: t.callers });
  }
  send({ kind: 'rate', ms: now(), counts });
}

rpc.exports = {
  configure(config) {
    for (const spec of config.targets) {
      if (!spec.name) throw new Error('a target needs a name');
      const wants = [];
      for (const e of [].concat(spec.export || [])) wants.push({ export: e });
      if (spec.rva !== undefined) wants.push({ rva: spec.rva });
      if (spec.iat !== undefined) wants.push({ iat: spec.iat });
      if (wants.length === 0) throw new Error(`${spec.name}: give export, rva or iat`);
      targets.push({ spec, wants, at: spec.at || 'leave', total: 0, sent: 0, limit: spec.limit || 10000, callers: {}, last: {} });
    }
    resolve();
    for (const t of targets) for (const want of t.wants) if (!want.done) send({ kind: 'pending', target: t.spec.name, want });
    Process.attachModuleObserver({ onAdded() { resolve(); } });
    const pendingIat = targets.some(t => t.wants.some(w => w.iat !== undefined && !w.done));
    if (pendingIat) { const timer = setInterval(() => { resolve(); if (!targets.some(t => t.wants.some(w => !w.done))) clearInterval(timer); }, 250); }
    const ms = config.interval_ms === undefined ? 2000 : config.interval_ms;
    if (ms > 0) interval = setInterval(report, ms);
    return true;
  },
  report() { report(); return true; }
};
