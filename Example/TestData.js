module.exports.permissions = [{
  code: 'DA',
  name: 'Docs adding'
}, {
  code: 'DR',
  name: 'Docs reading'
}, {
  code: 'DE',
  name: 'Docs editing'
}, {
  code: 'DD',
  name: 'Docs deleting'
}, {
  code: 'DM',
  name: 'Docs management',
  description: 'Manage docs (CURD)',
  includes: ['DA', 'DR', 'DE', 'DD']
}, {
  code: 'IR',
  name: 'Invoke role'
}, {
  code: 'RR',
  name: 'Revoke role'
}, {
  code: 'FR',
  name: 'Fetch role'
}, {
  code: 'RM',
  name: 'Role management',
  includes: ['IR', 'RR', 'FR']
}];

module.exports.roles = [{
  code: 'U',
  name: 'User',
  permissions: ['DA', 'DR']
}, {
  code: 'E',
  name: 'Editor',
  permissions: ['DM', 'DA']
}, {
  code: 'A',
  name: 'Admin',
  inherited: ['E'],
  permissions: ['FR']
}, {
  code: 'S',
  name: 'Super manager',
  description: 'The highest role.',
  inherited: ['A'],
  permissions: ['RM']
}];
