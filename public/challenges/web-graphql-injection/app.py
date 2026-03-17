#!/usr/bin/env python3
"""
GraphQL Introspection / Injection Challenge
Port: 5015

A GraphQL API with introspection enabled. There's a hidden
"flag" query that isn't documented in the UI. Use introspection
to discover it.
"""

import os
import graphene
from flask import Flask
from flask_graphql import GraphQLView

app = Flask(__name__)

FLAG = open(os.path.join(os.path.dirname(__file__), "flag.txt")).read().strip()


# ---------- Schema ----------

class UserType(graphene.ObjectType):
    id = graphene.Int()
    username = graphene.String()
    email = graphene.String()


class SecretType(graphene.ObjectType):
    flag = graphene.String()
    message = graphene.String()


USERS = [
    {"id": 1, "username": "alice", "email": "alice@example.com"},
    {"id": 2, "username": "bob", "email": "bob@example.com"},
    {"id": 3, "username": "charlie", "email": "charlie@example.com"},
]


class Query(graphene.ObjectType):
    # Public queries
    users = graphene.List(UserType)
    user = graphene.Field(UserType, id=graphene.Int(required=True))

    # Hidden query — not mentioned in the UI
    _admin_flag = graphene.Field(SecretType)

    def resolve_users(self, info):
        return [UserType(**u) for u in USERS]

    def resolve_user(self, info, id):
        for u in USERS:
            if u["id"] == id:
                return UserType(**u)
        return None

    def resolve__admin_flag(self, info):
        return SecretType(flag=FLAG, message="You found the hidden query!")


schema = graphene.Schema(query=Query)

app.add_url_rule(
    "/graphql",
    view_func=GraphQLView.as_view("graphql", schema=schema, graphiql=True),
)


@app.route("/")
def index():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>User API</title></head>
    <body>
    <h1>User Directory API</h1>
    <p>GraphQL endpoint: <a href="/graphql">/graphql</a></p>
    <h3>Example query:</h3>
    <pre>
{
  users {
    id
    username
    email
  }
}
    </pre>
    <p><small>Hint: there might be more queries than what's shown here...</small></p>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5015, debug=False)
