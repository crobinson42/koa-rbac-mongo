const app = require('koa')();
const rbacMongo = require('../');
const co = require('co');
const parse = require('co-body');
const compose = require('koa-compose');
const rbac = rbacMongo.rbac;
const mongodb = require('mongodb');
const MongoClient = mongodb.MongoClient;
const log = require('debug')('koa-rbac-mongo');

const ACCOUNTS = {
  'Amy': {
    roles: ['user']
  },
  'Bob': {
    roles: ['editor']
  },
  'Joker': {
    roles: ['user', 'admin']
  },
  'Luna': {
    roles: ['custom', 'user']
  },
  'Misery': {
    roles: ['super']
  }
};

co(function * () {
  const db = yield MongoClient.connect('mongodb://localhost/rbac-mongo');

  log('DB connected!');

  app.use(function * (next) {
    this.state.user = ACCOUNTS[this.query.username || 'Amy'];
    yield next;
  });

  app.use(rbacMongo({
    db,
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
    rbac.allow('doc.read'),
    function * (next) {
      if (this.method === 'GET') {
        this.body = { doc: 'Hello world!' };
      } else yield next;
    }
  ])));

  app.use(mount('/doc', compose([
    rbac.allow('doc.delete'),
    function * (next) {
      if (this.method === 'DELETE') {
        this.body = { messge: 'Remove doc success!' };
      } else yield next;
    }
  ])));

  app.use(mount('/roles', compose([
    rbac.allow('role.fetch'),
    function * (next) {
      if (this.method === 'GET') {
        this.body = (yield this.rbacMongo.Role.list()).map(role => role.code);
      } else yield next;
    }
  ])));

  app.use(mount('/roles', compose([
    rbac.allow('role.invoke'),
    function * (next) {
      if (this.method === 'POST') {
        const body = yield parse.json(this);
        this.body = yield this.rbacMongo.Role.create(body);
      } else yield next;
    }
  ])));

  app.use(mount('/roles', compose([
    rbac.allow('role.revoke'),
    function * (next) {
      if (this.method === 'DELETE') {
        this.body = yield this.rbacMongo.Role.remove(this.query.code);
      } else yield next;
    }
  ])));

  const request = require('supertest').agent(app.listen());
  const TestData = require('./TestData');

  // Init test data
  yield request.post('/testData').set('Content-Type', 'application/json').send(TestData);

  // Read doc
  console.log('Read doc with role [user]');
  var { body, status } = yield request.get('/doc?username=Amy');
  console.log(status, body);
  console.log('');

  // Delete doc.
  console.log('Delete doc with role [user] is forbidden.\n');
  yield request.delete('/doc?usernmae=Amy').expect(403);

  // Delete doc with role [editor]
  console.log('Delete doc with role [editor]');
  var { body, status } = yield request.delete('/doc?username=Bob');
  console.log(status, body);
  console.log('');

  // Fetch roles with role [admin]
  console.log('Fetch roles with role [admin]');
  var { body, status } = yield request.get('/roles?username=Joker');
  console.log(status, body);
  console.log('');

  // Invoke role with role [admin]
  console.log('Invoke role with role [admin] is forbidden.\n');
  yield request.post('/roles?username=Joker').set('Content-Type', 'application/json').send({
    code: 'custom',
    name: 'Custom',
    inherited: 'admin'
  }).expect(403);

  // Invoke role with role [super]
  console.log('Invoke role with role [super]');
  var { status, body } = yield request.post('/roles?username=Misery').set('Content-Type', 'application/json').send({
    code: 'custom',
    name: 'Custom',
    permissions: ['role.fetch']
  });
  console.log(status, body);
  console.log('');

  // Fetch roles with role [custom];
  console.log('Fetch roles with role [custom]');
  var { body, status } = yield request.get('/roles?username=Luna');
  console.log(status, body);
  console.log('');

  // Revoke role with role [super]
  console.log('Revoke role with role [super]');
  var { status, body } = yield request.delete('/roles?username=Misery&code=C');
  console.log(status, body);
  console.log('');

  // Fetch roles with role [super];
  console.log('Fetch roles with role [super]');
  var { body, status } = yield request.get('/roles?username=Misery');
  console.log(status, body);
  console.log('');

  // Delete doc.
  console.log('Delete doc with role [costom] is forbidden.\n');
  yield request.delete('/doc?usernmae=Luna').expect(403);

  // Clear test data
  yield request.delete('/testData');

}).catch(console.error);

