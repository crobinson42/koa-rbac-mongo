const rbac = require('koa-rbac');
const mongodb = require('mongodb');
const MongoClient = mongodb.MongoClient;
const debug = require('debug')('koa-rbac-mongo');
const Provider = require('./Provider');

module.exports = ({
  uri,
  permissionCollection = 'permissions',
  roleCollection = 'roles',
  mongoOptions = {},
  identity = function (ctx) {
    if (!ctx.state || !ctx.state.user) ctx.throw(401);
    return ctx.state.user;
  }
}) => {
  let db;
  let isNew = true;
  let rules = {};

  const Permission = function () {
    const c = db.collection(permissionCollection);
    return {
      collection: c,
      create: function * ({ code, name, description, includes = [] }) {
        if (!code || !name) this.throw(400, 'Permission should have code and name.');
        if (!Array.isArray(includes)) this.throw(400, 'Permission `includes` should be an array.');
        const p = yield c.findOne({ code });
        if (p) this.throw(400, 'Permission code should be unique.');
        for (let childCode of includes) {
          const child = yield c.findOne({ code: childCode });
          if (!child) this.throw(400, `Child permission '${childCode}' is not exists, please add it first`);
        }
        isNew = true;
        return yield c.insertOne({
          code,
          name,
          description,
          includes
        });
      }.bind(this),
      get: function * (code) {
        return yield c.findOne({ code });
      },
      list: function * () {
        return yield c.find().toArray();
      },
      remove: function * (code) {
        isNew = true;
        yield c.removeOne({ code });
      }
    };
  };

  const Role = function () {
    const c = db.collection(roleCollection);
    const pc = db.collection(permissionCollection);
    return {
      collection: c,
      create: function * ({ code, name, description, inherited = [], permissions = [] }) {
        if (!code || !name) this.throw(400, 'Role should have code and name');
        if (!Array.isArray(inherited)) this.throw(400, 'Permission `inherited` should be an array.');
        if (!Array.isArray(permissions)) this.throw(400, 'Permission `permissions` should be an array.');
        const role = yield c.findOne({ code });
        if (role) this.throw(400, 'Role code should be unique.');
        for (let parentRole of inherited) {
          const parent = yield c.findOne({ code: parentRole });
          if (!parent) this.throw(400, `Parent role '${parentRole}' is not exists, please add it first.`);
        }
        for (let permissionCode of permissions) {
          const permission = yield pc.findOne({ code: permissionCode });
          if (!permission) this.throw(400, `Permission '${permissionCode}' is not exists, please add it first.`);
        }
        isNew = true;
        return yield c.insertOne({
          code,
          name,
          description,
          inherited,
          permissions
        });
      }.bind(this),
      list: function * () {
        return yield c.find().toArray();
      },
      remove: function * (code) {
        isNew = true;
        yield c.removeOne({ code });
      }
    };
  };

  return function * (next) {
    if (!db) {
      db = yield MongoClient.connect(uri, mongoOptions);
      yield db.collection(permissionCollection).createIndex({ code: 1 }, { unique: 1 });
      yield db.collection(roleCollection).createIndex({ code: 1 }, { unique: 1 });

      debug('DB connected!');
    }

    this.rbacMongo = {
      Permission: Permission.bind(this)(),
      Role: Role.bind(this)()
    };

    if (isNew) {
      const roles = yield this.rbacMongo.Role.list();

      for (let role of roles) {
        const p = [];
        for (let code of role.permissions) {
          const permission = yield this.rbacMongo.Permission.get(code);
          if (permission && permission.includes.length > 0) p.push(...permission.includes);
          else p.push(code);
        }
        rules[role.code] = {
          inherited: role.inherited,
          permissions: p
        };
      }

      isNew = false;
    }

    yield rbac.middleware({
      rbac: new rbac.RBAC({
        provider: new Provider(rules)
      }),
      identity
    }).bind(this)(next);
  }
};

module.exports.rbac = rbac;