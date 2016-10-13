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
    const fetch = function * (code) {
      return yield c.findOne({ code });
    };
    const create = function * ({ code, name, meta = {}, description }) {
      if (!code || !name) this.throw(400, 'Permission should have code and name.');
      const p = yield fetch(code);
      if (p) this.throw(400, 'Permission code should be unique.');
      isNew = true;
      const result = yield c.insertOne({
        code,
        name,
        meta,
        description
      });
      return yield c.findOne({ _id: result.insertedId });
    }.bind(this);
    const update = function * ({ code, name, meta = {}, description }) {
      const permission = yield fetch(code);
      if (permission) {
        isNew = true;
        return yield c.updateOne({ code }, {
          $set: {
            name,
            meta,
            description
          }
        });
      } else {
        return yield create({ code, name, meta, description });
      }
    };
    const list = function * (query) {
      return yield c.find(query).toArray();
    };
    const remove = function * (code) {
      isNew = true;
      yield c.removeOne({ code });
    };
    return {
      collection: c,
      create,
      fetch,
      update,
      list,
      remove
    };
  };

  const Role = function () {
    const c = db.collection(roleCollection);
    const pc = db.collection(permissionCollection);
    const fetch = function * (code) {
      return yield c.findOne({ code });
    };
    const create = function * ({ code, name, meta, description, permissions = [] }) {
      if (!code || !name) this.throw(400, 'Role should have code and name');
      if (!Array.isArray(permissions)) this.throw(400, 'Permission `permissions` should be an array.');
      const role = yield fetch(code);
      if (role) this.throw(400, 'Role code should be unique.');
      for (let permissionCode of permissions) {
        const permission = yield pc.findOne({ code: permissionCode });
        if (!permission) this.throw(400, `Permission '${permissionCode}' is not exists, please add it first.`);
      }
      isNew = true;
      const result = yield c.insertOne({
        code,
        name,
        meta,
        description,
        permissions
      });
      return yield c.findOne({ _id: result.insertedId });
    }.bind(this);
    const update = function * ({ code, name, meta, description, permissions = [] }) {
      const role = yield fetch(code);
      if (role) {
        isNew = true;
        return yield c.updateOne({ code }, {
          $set: {
            name,
            meta,
            description,
            permissions
          }
        });
      } else {
        return yield create({ code, name, meta, description, permissions });
      }
    };
    const list = function * (query) {
      return yield c.find(query).toArray();
    };
    const remove = function * (code) {
      isNew = true;
      yield c.removeOne({ code });
    };
    return {
      collection: c,
      create,
      update,
      fetch,
      list,
      remove
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
        rules[role.code] = {
          inherited: role.inherited,
          permissions: role.permissions
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