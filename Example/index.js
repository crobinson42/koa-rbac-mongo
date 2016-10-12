const app = require('koa')();
const rbacMongo = require('../');
const co = require('co');
const parse = require('co-body');
const compose = require('koa-compose');
const rbac = rbacMongo.rbac;

const ACCOUNTS = {
  'Amy': {
    roles: ['U']
  },
  'Bob': {
    roles: ['E']
  },
  'Joker': {
    roles: ['U', 'A']
  },
  'Luna': {
    roles: ['C', 'U']
  },
  'Misery': {
    roles: ['S']
  }
};

app.use(function * (next) {
  this.state.user = ACCOUNTS[this.query.username || 'Amy'];
  yield next;
});

app.use(rbacMongo({
  uri: 'mongodb://localhost/rbac-mongo',
  permissionCollection: 'permissions',
  roleCollection: 'roles',
  mongoOptions: {},
  identity: function (ctx) {
    if (!ctx.state || !ctx.state.user) ctx.throw(401);
    return ctx.state.user;
  }
}));

app.on('error', console.error);

const mount = function (path, middleware) {
  return function * (next) {
    if (path === this.path) {
      yield middleware.bind(this)(next);
    } else {
      yield next;
    }
  }
};

app.use(mount('/testData', function * () {
  if (this.method === 'POST') {
    const body = yield parse.json(this);
    for (let permission of body.permissions) {
      yield this.rbacMongo.Permission.create(permission);
    }
    console.log('Import permissions success.');
    for (let role of body.roles) {
      yield this.rbacMongo.Role.create(role);
    }
    console.log('Import roles success.');
  } else if (this.method === 'DELETE') {
    yield this.rbacMongo.Permission.collection.removeMany();
    console.log('Remove permissions success.');
    yield this.rbacMongo.Role.collection.removeMany();
    console.log('Remove roles success.');
  }
}));

app.use(mount('/doc', compose([
  rbac.allow('DR'),
  function * (next) {
    if (this.method === 'GET') {
      this.body = { doc: 'Hello world!' };
    } else yield next;
  }
])));

app.use(mount('/doc', compose([
  rbac.allow('DD'),
  function * (next) {
    if (this.method === 'DELETE') {
      this.body = { messge: 'Remove doc success!' };
    } else yield next;
  }
])));

app.use(mount('/roles', compose([
  rbac.allow('FR'),
  function * (next) {
    if (this.method === 'GET') {
      this.body = (yield this.rbacMongo.Role.list()).map(role => role.code);
    } else yield next;
  }
])));

app.use(mount('/roles', compose([
  rbac.allow('IR'),
  function * (next) {
    if (this.method === 'POST') {
      const body = yield parse.json(this);
      this.body = yield this.rbacMongo.Role.create(body);
    } else yield next;
  }
])));

app.use(mount('/roles', compose([
  rbac.allow('RR'),
  function * (next) {
    if (this.method === 'DELETE') {
      this.body = yield this.rbacMongo.Role.remove(this.query.code);
    } else yield next;
  }
])));

const request = require('supertest').agent(app.listen());
const TestData = require('./TestData');

co(function * () {
  // Init test data
  yield request.post('/testData').set('Content-Type', 'application/json').send(TestData);

  // Read doc
  console.log('Read doc with role [U]');
  var { body, status } = yield request.get('/doc?username=Amy');
  console.log(status, body);
  console.log('');

  // Delete doc.
  console.log('Delete doc with role [U] is forbidden.\n');
  yield request.delete('/doc?usernmae=Amy').expect(403);

  // Delete doc with role [E]
  console.log('Delete doc with role [E]');
  var { body, status } = yield request.delete('/doc?username=Bob');
  console.log(status, body);
  console.log('');

  // Fetch roles with role [A]
  console.log('Fetch roles with role [A]');
  var { body, status } = yield request.get('/roles?username=Joker');
  console.log(status, body);
  console.log('');

  // Invoke role with role [A]
  console.log('Invoke role with role [A] is forbidden.\n');
  yield request.post('/roles?username=Joker').set('Content-Type', 'application/json').send({
    code: 'C',
    name: 'Custom',
    inherited: 'A'
  }).expect(403);

  // Invoke role with role [S]
  console.log('Invoke role with role [S]');
  var { status, body } = yield request.post('/roles?username=Misery').set('Content-Type', 'application/json').send({
    code: 'C',
    name: 'Custom',
    inherited: ['A']
  });
  console.log(status, body);
  console.log('');

  // Fetch roles with role [C];
  console.log('Fetch roles with role [C]');
  var { body, status } = yield request.get('/roles?username=Luna');
  console.log(status, body);
  console.log('');

  // Revoke role with role [S]
  console.log('Revoke role with role [S]');
  var { status, body } = yield request.delete('/roles?username=Misery&code=C');
  console.log(status, body);
  console.log('');

  // Fetch roles with role [S];
  console.log('Fetch roles with role [C]');
  var { body, status } = yield request.get('/roles?username=Misery');
  console.log(status, body);
  console.log('');

  // Delete doc.
  console.log('Delete doc with role [C] is forbidden.\n');
  yield request.delete('/doc?usernmae=Luna').expect(403);

  // Clear test data
  yield request.delete('/testData');
}).catch(console.error);