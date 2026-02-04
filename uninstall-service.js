const { Service } = require('node-windows');
const path = require('path');

// Production path - must match install-service.js
const APP_ROOT = 'C:\\Apps\\Apps\\spl-ca';

const svc = new Service({
  name: '_spl-ca-mgr',
  script: path.join(APP_ROOT, 'server.js')
});

svc.on('uninstall', () => {
  console.log('Service uninstalled successfully.');
});

svc.on('stop', () => {
  console.log('Service stopped.');
});

svc.on('error', (err) => {
  console.error('Error:', err);
});

// Stop first, then uninstall
svc.uninstall();
