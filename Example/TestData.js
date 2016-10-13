module.exports.permissions = [{
  code: 'doc.add',
  name: 'Docs adding'
}, {
  code: 'doc.read',
  name: 'Docs reading'
}, {
  code: 'doc.edit',
  name: 'Docs editing'
}, {
  code: 'doc.delete',
  name: 'Docs deleting'
}, {
  code: 'role.invoke',
  name: 'Invoke role'
}, {
  code: 'role.revoke',
  name: 'Revoke role'
}, {
  code: 'role.fetch',
  name: 'Fetch role'
}];

module.exports.roles = [{
  code: 'user',
  name: 'User',
  permissions: ['doc.add', 'doc.read']
}, {
  code: 'editor',
  name: 'Editor',
  permissions: ['doc.add', 'doc.read', 'doc.edit', 'doc.delete']
}, {
  code: 'admin',
  name: 'Admin',
  permissions: ['doc.add', 'doc.read', 'doc.edit', 'doc.delete', 'role.fetch']
}, {
  code: 'super',
  name: 'Super manager',
  description: 'The highest role.',
  permissions: ['doc.add', 'doc.read', 'doc.edit', 'doc.delete', 'role.fetch', 'role.invoke', 'role.revoke']
}];
