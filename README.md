## koa-rbac-mongo ![NPM version](https://img.shields.io/npm/v/koa-rbac-mongo.svg?style=flat)
<a href="https://communityinviter.com/apps/koa-js/koajs" rel="KoaJs Slack Community">![KoaJs Slack](https://img.shields.io/badge/Koa.Js-Slack%20Channel-Slack.svg?longCache=true&style=for-the-badge)</a>

 Save the rbac rules to mongodb for dynamic rbac setup and check.

### Installation
```bash
$ npm install koa-rbac-mongo --save
```

### Example
```js
const rbacMongo = require('koa-rbac-mongo');
const app = require('koa')();
const rbac = rbacMongo.rbac;

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

app.use(rbac.allow(['read docs']));

app.use(function *() {
  this.body = 'Protected docs';
});

```
check more details in `Example/index.js`

### API
#### rbacMongo
##### options {`Object`}
* uri {`String`} `required` The mongo uri to connect the mongodb.
* mongoOptions {`Object`} `optional` The mongo connect options, [check details](http://mongodb.github.io/node-mongodb-native/2.2/reference/connecting/connection-settings/).
* permissionCollection {`String`} `required` `default: 'permissions'` The collection to save the permissions.
* roleCollection {`String`} `required` `default: 'roles'` The collection to save the roles.
* identity {`Function`} [check details](https://github.com/yanickrochon/koa-rbac)
```
// Default identity
function (ctx) {
  if (!ctx.state || !ctx.state.user) ctx.throw(401);
  return ctx.state.user;
}
```
#### rbacMongo.rbac
The [koa-rbac](https://github.com/yanickrochon/koa-rbac) instance;

A `rbacMongo` object will attach to koa context.
#### ctx.rbacMongo.Permission {`Object`}
* collection {[Collection](http://mongodb.github.io/node-mongodb-native/2.2/api/Collection.html)} The collection where tokens saved.
* fetch {`GeneratorFunction(code)`} Fetch a permission data by code from database.
* create {`GeneratorFunction(permission)`} Create a permission and save it to mongodb.
* update {`GeneratorFunction(permission)`} Update a permission.
* list {`GeneratorFunction()`} List all permissions data from database.
* remove {`GeneratorFunction(code)`} Remove a permission data by code.

#### ctx.rbacMongo.Role {`Object`}
* collection {[Collection](http://mongodb.github.io/node-mongodb-native/2.2/api/Collection.html)} The collection where tokens saved.
* fetch {`GeneratorFunction(code)`} Fetch a role data by code from database.
* create {`GeneratorFunction(role)`} Create a role and save it to mongodb.
* update {`GeneratorFunction(role)`} Update a role.
* grant {`GeneratorFunction(code, permissionCode)`} Grant the permission to the role.
* revoke {`GeneratorFunction(code, permissionCode)`} Revoke the permission to the role.
* list {`GeneratorFunction()`} List all roles data from database.
* remove {`GeneratorFunction(code)`} Remove a role data by code.

The `permission` data is like:
```javascript
const permission = {
  code: 'doc.read', // The unique code of the permission
  name: 'Doc reading', // The friendly name for display on front-end.
  description: 'Reading docs only.', // The optional description of the permission
  meta: { // Some extra data for business use.
    someKey: 'someValue'
  }
}
```
The `role` data is like;
```javascript
const role = {
  code: 'editor', // The unique code of the permission,
  name: 'The editor', // The friendly name for display on front-end.
  description: 'The role can edit the docs', // The optional description of the role
  meta: { // Some extra data for business use.
    someKey: 'someValue'
  },
  permissions: ['doc.edit'] // Some extra permissions the role required
}
```
Notice: Everytime permissions or roles changed, `rbacMongo` will regenerate the rules from all data.

***Notice:*** I used inherited feature in the previous version `0.1.x`, but it's no use at all in my
application development, so I removed it in `0.2.x`. It's an break change!!!


### Contributing
- Fork this Repo first
- Clone your Repo
- Install dependencies by `$ npm install`
- Checkout a feature branch
- Feel free to add your features
- Make sure your features are fully tested
- Publish your local branch, Open a pull request
- Enjoy hacking <3

### MIT license
Copyright (c) 2016 Misery Lee &lt;miserylee@foxmail.com&gt;

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the &quot;Software&quot;), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED &quot;AS IS&quot;, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

---
![docor]()
built upon love by [docor](git+https://github.com/turingou/docor.git) v0.3.0
