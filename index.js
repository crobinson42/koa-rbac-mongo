const rbac = require('koa-rbac');
const mongodb = require('mongodb');
const MongoClient = mongodb.MongoClient;
const log = require('debug')('koa-rbac-mongo');
const Provider = require('./Provider');
const co = require('co');

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
  let usedPermissions = [];

  const Permission = function () {
    const c = db.collection(permissionCollection);
    const rc = db.collection(roleCollection);
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
    const update = function * (permission = {}) {
      if (!permission.code) this.throw(400, 'Permission should have a code');
      const p = yield fetch(permission.code);
      if (p) {
        isNew = true;
        return yield c.updateOne({ code: permission.code }, {
          $set: permission
        });
      } else {
        return yield create(permission);
      }
    }.bind(this);
    const list = function * (query) {
      return yield c.find(query).toArray();
    };
    const remove = function * (code) {
      // Remove all roles's permission
      const roles = yield rc.find().toArray();
      yield rc.updateMany({ code: { $in: roles.map(role => role.code) } }, {
        $pull: { permissions: code }
      });
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
    const update = function * (role = {}) {
      if (!role.code) this.throw(400, 'Role should have a code');
      const r = yield fetch(role.code);
      if (r) {
        for (let permissionCode of role.permissions || []) {
          const permission = yield pc.findOne({ code: permissionCode });
          if (!permission) this.throw(400, `Permission '${permissionCode}' is not exists, please add it first.`);
        }
        isNew = true;
        return yield c.updateOne({ code: role.code }, {
          $set: role
        });
      } else {
        return yield create(role);
      }
    }.bind(this);
    const grant = function * (code, permissionCode) {
      const permission = yield pc.findOne({ code: permissionCode });
      if (!permission) this.throw(400, `Permission '${permissionCode}' is not exists, please add it first.`);
      yield c.updateOne({ code }, { $push: { permissions: permissionCode } });
      isNew = true;
      return yield fetch(code);
    }.bind(this);
    const revoke = function * (code, permissionCode) {
      yield c.updateOne({ code }, { $pull: { permissions: permissionCode } });
      isNew = true;
      return yield fetch(code);
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
      grant,
      revoke,
      list,
      remove
    };
  };

  const connectDB = function * () {
    // If db is connecting, wait for a moment. If it's still connecting, connect it again.
    if (db === 'connecting') yield new Promise(resolve => setTimeout(resolve, 500));
    if (db === 'connecting') db = null;
    if (!db) {
      db = 'connecting';
      try {
        db = yield MongoClient.connect(uri, mongoOptions);
        yield db.collection(permissionCollection).createIndex({ code: 1 }, { unique: 1 });
        yield db.collection(roleCollection).createIndex({ code: 1 }, { unique: 1 });

        log('DB connected!');
      } catch (err) {
        log(`DB connected failed. Error: ${err.message}`);
        db = null;
      }
    }
  };

  const middleware = function * (next) {
    yield connectDB();

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
  };

  middleware.usedPermissions = usedPermissions;

  middleware.check = function (code, { name, meta, description }, handler) {

    if (name && !usedPermissions.includes[code]) {
      usedPermissions.push(code);
      co(function * () {
        yield connectDB();
        const c = db.collection(permissionCollection);
        const permission = yield c.findOne({ code });
        if (permission) {
          yield c.updateOne({ code }, {
            $set: {
              name,
              description,
              meta
            }
          });
          log(`Update permission ${name}[${code}] success!`);
        } else {
          yield c.insertOne({
            code,
            name,
            description,
            meta
          });
          log(`Create permission ${name}[${code}] success!`);
        }
      }).catch(err => {
        throw err;
      });
    }

    return function * (next) {
      if (handler) {
        next = handler.bind(this)(next);
      }
      yield rbac.allow([code]).bind(this)(next);
    }
  };

  return middleware;
};

module.exports.rbac = rbac;
