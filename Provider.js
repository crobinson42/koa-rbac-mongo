const rbac = require('koa-rbac');

class RBACProvider extends rbac.RBAC.providers.JsonProvider {

  getRoles(user) {
    return (user && user.roles || []).reduce((memo, cur) => {
      memo[cur] = null;
      return memo;
    }, {});
  }

  getPermissions(role) {
    return this._rules && this._rules[role] && this._rules[role]['permissions'] || [];
  }

  getAttributes(role) {
    return this._rules && this._rules[role] && this._rules[role]['attributes'] || [];
  }

}

module.exports = RBACProvider;