const { Service } = require('node-windows');
const path = require('path');

// Production path - change this if different
const APP_ROOT = 'C:\\Apps\\Apps\\spl-ca';

const svc = new Service({
  name: '_spl-ca-mgr',
  description: 'SPL Pathology Associates Certificate Authority Web Service',
  script: path.join(APP_ROOT, 'server.js'),
  workingDirectory: APP_ROOT,
  nodeOptions: [],
  env: [
    { name: 'NODE_ENV', value: 'production' },
    { name: 'NODE_EXTRA_CA_CERTS', value: 'C:\\CAROOT\\CA.pem' }
  ],
  // Restart on crash
  abortOnError: false,
  wait: 2,
  grow: 0.5,
  maxRestarts: 10,
  // Log file location
  logpath: APP_ROOT
});

svc.on('install', () => {
  console.log('Service installed successfully.');
  console.log('Starting service...');
  svc.start();
});

svc.on('start', () => {
  console.log('Service started.');
  console.log('');
  console.log('Manage with:');
  console.log('  net start _spl-ca-mgr');
  console.log('  net stop _spl-ca-mgr');
  console.log('  sc query _spl-ca-mgr');
});

svc.on('alreadyinstalled', () => {
  console.log('Service is already installed.');
});

svc.on('error', (err) => {
  console.error('Error:', err);
});

svc.install();
