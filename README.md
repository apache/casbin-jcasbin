# jCasbin

[![GitHub Actions](https://github.com/casbin/jcasbin/workflows/build/badge.svg)](https://github.com/casbin/jcasbin/actions)
[![codecov](https://codecov.io/gh/casbin/jcasbin/branch/master/graph/badge.svg?token=pKOEodQ3q9)](https://codecov.io/gh/casbin/jcasbin)
[![javadoc](https://javadoc.io/badge2/org.casbin/jcasbin/javadoc.svg)](https://javadoc.io/doc/org.casbin/jcasbin)
[![Maven Central](https://img.shields.io/maven-central/v/org.casbin/jcasbin.svg)](https://mvnrepository.com/artifact/org.casbin/jcasbin/latest)
[![Release](https://img.shields.io/github/release/casbin/jcasbin.svg)](https://github.com/casbin/jcasbin/releases/latest)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

**News**: still worry about how to write the correct jCasbin policy? `Casbin online editor` is coming to help! Try it at: https://casbin.org/editor/

![casbin Logo](casbin-logo.png)

jCasbin is a powerful and efficient open-source access control library for Java projects. It provides support for enforcing authorization based on various [access control models](https://en.wikipedia.org/wiki/Computer_security_model).

## All the languages supported by Casbin:

| [![golang](https://casbin.org/img/langs/golang.png)](https://github.com/casbin/casbin) | [![java](https://casbin.org/img/langs/java.png)](https://github.com/casbin/jcasbin) | [![nodejs](https://casbin.org/img/langs/nodejs.png)](https://github.com/casbin/node-casbin) | [![php](https://casbin.org/img/langs/php.png)](https://github.com/php-casbin/php-casbin) |
|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| [Casbin](https://github.com/casbin/casbin)                                             | [jCasbin](https://github.com/casbin/jcasbin)                                        | [node-Casbin](https://github.com/casbin/node-casbin)                                        | [PHP-Casbin](https://github.com/php-casbin/php-casbin)                                   |
| production-ready                                                                       | production-ready                                                                    | production-ready                                                                            | production-ready                                                                         |

| [![python](https://casbin.org/img/langs/python.png)](https://github.com/casbin/pycasbin) | [![dotnet](https://casbin.org/img/langs/dotnet.png)](https://github.com/casbin-net/Casbin.NET) | [![c++](https://casbin.org/img/langs/cpp.png)](https://github.com/casbin/casbin-cpp) | [![rust](https://casbin.org/img/langs/rust.png)](https://github.com/casbin/casbin-rs) |
|------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| [PyCasbin](https://github.com/casbin/pycasbin)                                           | [Casbin.NET](https://github.com/casbin-net/Casbin.NET)                                         | [Casbin-CPP](https://github.com/casbin/casbin-cpp)                                   | [Casbin-RS](https://github.com/casbin/casbin-rs)                                      |
| production-ready                                                                         | production-ready                                                                               | beta-test                                                                            | production-ready                                                                      |

## Table of contents

- [Supported models](#supported-models)
- [How it works?](#how-it-works)
- [Features](#features)
- [Installation](#installation)
- [Documentation](#documentation)
- [Online editor](#online-editor)
- [Tutorials](#tutorials)
- [Get started](#get-started)
- [Policy management](#policy-management)
- [Policy persistence](#policy-persistence)
- [Role manager](#role-manager)
- [Examples](#examples)
- [Middlewares](#middlewares)
- [Our adopters](#our-adopters)
- [Spring Boot support](#spring-boot-support)

## Supported models

1. [**ACL (Access Control List)**](https://en.wikipedia.org/wiki/Access_control_list)
2. **ACL with [superuser](https://en.wikipedia.org/wiki/Superuser)**
3. **ACL without users**: especially useful for systems that don't have authentication or user log-ins.
4. **ACL without resources**: some scenarios may target for a type of resources instead of an individual resource by using permissions like `write-article`, `read-log`. It doesn't control the access to a specific article or log.
5. **[RBAC (Role-Based Access Control)](https://en.wikipedia.org/wiki/Role-based_access_control)**
6. **RBAC with resource roles**: both users and resources can have roles (or groups) at the same time.
7. **RBAC with domains/tenants**: users can have different role sets for different domains/tenants.
8. **[ABAC (Attribute-Based Access Control)](https://en.wikipedia.org/wiki/Attribute-Based_Access_Control)**: syntax sugar like `resource.Owner` can be used to get the attribute for a resource.
9. **[RESTful](https://en.wikipedia.org/wiki/Representational_state_transfer)**: supports paths like `/res/*`, `/res/:id` and HTTP methods like `GET`, `POST`, `PUT`, `DELETE`.
10. **Deny-override**: both allow and deny authorizations are supported, deny overrides the allow.
11. **Priority**: the policy rules can be prioritized like firewall rules.

## How it works?

In jCasbin, an access control model is abstracted into a CONF file based on the **PERM metamodel (Policy, Effect, Request, Matchers)**. So switching or upgrading the authorization mechanism for a project is just as simple as modifying a configuration. You can customize your own access control model by combining the available models. For example, you can get RBAC roles and ABAC attributes together inside one model and share one set of policy rules.

The most basic and simplest model in jCasbin is ACL. ACL's model CONF is:

```ini
# Request definition
[request_definition]
r = sub, obj, act

# Policy definition
[policy_definition]
p = sub, obj, act

# Policy effect
[policy_effect]
e = some(where (p.eft == allow))

# Matchers
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

An example policy for ACL model is like:

```
p, alice, data1, read
p, bob, data2, write
```

It means:

- alice can read data1
- bob can write data2

## Features

What jCasbin does:

1. enforce the policy in the classic `{subject, object, action}` form or a customized form as you defined, both allow and deny authorizations are supported.
2. handle the storage of the access control model and its policy.
3. manage the role-user mappings and role-role mappings (aka role hierarchy in RBAC).
4. support built-in superuser like `root` or `administrator`. A superuser can do anything without explicit permissions.
5. multiple built-in operators to support the rule matching. For example, `keyMatch` can map a resource key `/foo/bar` to the pattern `/foo*`.

What jCasbin does NOT do:

1. authentication (aka verify `username` and `password` when a user logs in)
2. manage the list of users or roles. I believe it's more convenient for the project itself to manage these entities. Users usually have their passwords, and jCasbin is not designed as a password container. However, jCasbin stores the user-role mapping for the RBAC scenario.

## Installation

For Maven:

```
<dependency>
  <groupId>org.casbin</groupId>
  <artifactId>jcasbin</artifactId>
  <version>1.x.y (replace with latest version)</version>
</dependency>
```

## Documentation

https://casbin.org/docs/overview

## Online editor

You can also use the online editor (https://casbin.org/editor/) to write your jCasbin model and policy in your web browser. It provides functionality such as `syntax highlighting` and `code completion`, just like an IDE for a programming language.

## Tutorials

https://casbin.org/docs/tutorials

## Get started

1. New a jCasbin enforcer with a model file and a policy file:

   ```java
   Enforcer enforcer = new Enforcer("path/to/model.conf", "path/to/policy.csv");
   ```

Note: you can also initialize an enforcer with policy in DB instead of file, see [Policy persistence](#policy-persistence) section for details.

2. Add an enforcement hook into your code right before the access happens:

   ```java
   String sub = "alice"; // the user that wants to access a resource.
   String obj = "data1"; // the resource that is going to be accessed.
   String act = "read"; // the operation that the user performs on the resource.

   if (enforcer.enforce(sub, obj, act) == true) {
       // permit alice to read data1
   } else {
       // deny the request, show an error
   }
   ```

3. Besides the static policy file, jCasbin also provides API for permission management at run-time. For example, You can get all the roles assigned to a user as below:

   ```java
   Roles roles = enforcer.getRoles("alice");
   ```

See [Policy management APIs](#policy-management) for more usage.

4. Please refer to the [src/test](https://github.com/casbin/jcasbin/tree/master/src/test) package for more usage.

## Policy management

jCasbin provides two sets of APIs to manage permissions:

- [Management API](https://github.com/casbin/jcasbin/blob/master/src/main/java/org/casbin/jcasbin/main/ManagementEnforcer.java): the primitive API that provides full support for jCasbin policy management. See [here](https://github.com/casbin/jcasbin/blob/master/src/test/java/org/casbin/jcasbin/main/ManagementAPIUnitTest.java) for examples.
- [RBAC API](https://github.com/casbin/jcasbin/blob/master/src/main/java/org/casbin/jcasbin/main/Enforcer.java): a more friendly API for RBAC. This API is a subset of Management API. The RBAC users could use this API to simplify the code. See [here](https://github.com/casbin/jcasbin/blob/master/src/test/java/org/casbin/jcasbin/main/RbacAPIUnitTest.java) for examples.

We also provide a [web-based UI](https://github.com/casbin/web-ui) for model management and policy management:

![model editor](https://hsluoyz.github.io/casbin/ui_model_editor.png)

![policy editor](https://hsluoyz.github.io/casbin/ui_policy_editor.png)

## Policy persistence

https://casbin.org/docs/adapters

## Role manager

https://casbin.org/docs/role-managers

## Expression Validation and Cross-Platform Compatibility

Starting from version 1.98.1, jCasbin validates expressions to ensure cross-platform compatibility with other Casbin implementations (Go, Node.js, Python, .NET, etc.).

### Restricted Syntax

The following AviatorScript-specific features are **not allowed** in `eval()` expressions and policy rules:

- **Namespace methods**: `seq.list()`, `string.startsWith()`, `string.endsWith()`, `math.sqrt()`, etc.
- **Advanced control structures**: `lambda`, `let`, `fn`, `for`, `while`, `return`, `if-then-else`, `->`

These features are restricted because they are specific to AviatorScript and would make policies incompatible with other Casbin implementations.

### Allowed Syntax

The following standard Casbin syntax is fully supported:

- **Operators**: `&&`, `||`, `==`, `!=`, `<`, `>`, `<=`, `>=`, `+`, `-`, `*`, `/`, `!`, `in`
- **Built-in functions**: `g()`, `keyMatch()`, `keyMatch2-5()`, `regexMatch()`, `ipMatch()`, `globMatch()`, `timeMatch()`, `eval()`
- **Custom functions**: Users can still register custom functions using `enforcer.addFunction()`
- **Variable access**: `r.attr`, `p.attr` (automatically escaped to `r_attr`, `p_attr`)

### Example

```java
// ❌ NOT allowed - AviatorScript-specific syntax
"eval(seq.list('admin', 'editor'))"
"eval(string.startsWith(r.path, '/admin'))"

// ✅ Allowed - Standard Casbin syntax
"eval(r.age > 18 && r.age < 65)"
"r.role in ('admin', 'editor')"  // Converted to include(tuple(...), ...)
"g(r.sub, p.sub) && keyMatch(r.path, p.path)"
```

If an expression contains restricted syntax, it will be logged as a warning and return `false`.

## Examples

| Model                     | Model file                                                                                                                        | Policy file                                                                                                                       |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| ACL                       | [basic_model.conf](https://github.com/casbin/jcasbin/blob/master/examples/basic_model.conf)                                       | [basic_policy.csv](https://github.com/casbin/jcasbin/blob/master/examples/basic_policy.csv)                                       |
| ACL with superuser        | [basic_model_with_root.conf](https://github.com/casbin/jcasbin/blob/master/examples/basic_with_root_model.conf)                   | [basic_policy.csv](https://github.com/casbin/jcasbin/blob/master/examples/basic_policy.csv)                                       |
| ACL without users         | [basic_model_without_users.conf](https://github.com/casbin/jcasbin/blob/master/examples/basic_without_users_model.conf)           | [basic_policy_without_users.csv](https://github.com/casbin/jcasbin/blob/master/examples/basic_without_users_policy.csv)           |
| ACL without resources     | [basic_model_without_resources.conf](https://github.com/casbin/jcasbin/blob/master/examples/basic_without_resources_model.conf)   | [basic_policy_without_resources.csv](https://github.com/casbin/jcasbin/blob/master/examples/basic_without_resources_policy.csv)   |
| RBAC                      | [rbac_model.conf](https://github.com/casbin/jcasbin/blob/master/examples/rbac_model.conf)                                         | [rbac_policy.csv](https://github.com/casbin/jcasbin/blob/master/examples/rbac_policy.csv)                                         |
| RBAC with resource roles  | [rbac_model_with_resource_roles.conf](https://github.com/casbin/jcasbin/blob/master/examples/rbac_with_resource_roles_model.conf) | [rbac_policy_with_resource_roles.csv](https://github.com/casbin/jcasbin/blob/master/examples/rbac_with_resource_roles_policy.csv) |
| RBAC with domains/tenants | [rbac_model_with_domains.conf](https://github.com/casbin/jcasbin/blob/master/examples/rbac_with_domains_model.conf)               | [rbac_policy_with_domains.csv](https://github.com/casbin/jcasbin/blob/master/examples/rbac_with_domains_policy.csv)               |
| ABAC                      | [abac_model.conf](https://github.com/casbin/jcasbin/blob/master/examples/abac_model.conf)                                         | N/A                                                                                                                               |
| RESTful                   | [keymatch_model.conf](https://github.com/casbin/jcasbin/blob/master/examples/keymatch_model.conf)                                 | [keymatch_policy.csv](https://github.com/casbin/jcasbin/blob/master/examples/keymatch_policy.csv)                                 |
| Deny-override             | [rbac_model_with_deny.conf](https://github.com/casbin/jcasbin/blob/master/examples/rbac_with_deny_model.conf)                     | [rbac_policy_with_deny.csv](https://github.com/casbin/jcasbin/blob/master/examples/rbac_with_deny_policy.csv)                     |
| Priority                  | [priority_model.conf](https://github.com/casbin/jcasbin/blob/master/examples/priority_model.conf)                                 | [priority_policy.csv](https://github.com/casbin/jcasbin/blob/master/examples/priority_policy.csv)                                 |

## Middlewares

Authz middlewares for web frameworks: https://casbin.org/docs/middlewares

## Our adopters

https://casbin.org/docs/adopters

## Spring Boot support

We provide Spring Boot support, you can use [casbin-spring-boot-starter](https://github.com/jcasbin/casbin-spring-boot-starter) to quickly develop in SpringBoot

In casbin-spring-boot-starter, we made the following adjustments:

1. Rewrite JDBCAdapter to support a variety of commonly used JDBC databases
2. Implement RedisWatcher
3. IDEA Editor Configuration Tips
4. Provide default configuration, automatic assembly
5. SpringSecurity integration (future)
6. Shiro integration (future)

https://github.com/jcasbin/casbin-spring-boot-starter

## Contributors

This project exists thanks to all the people who contribute.
<a href="https://github.com/casbin/jcasbin/graphs/contributors"><img src="https://opencollective.com/jcasbin/contributors.svg?width=890&button=false" /></a>

## Star History

[![Star History Chart](https://star-history.dera.page/svg?repos=casbin/jcasbin&type=Date)](https://star-history.dera.page/#casbin/jcasbin&type=date)

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

## Contact

If you have any issues or feature requests, please contact us. PR is welcomed.

- https://github.com/casbin/jcasbin/issues
- https://discord.gg/S5UjpzGZjN
