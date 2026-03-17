#!/bin/bash
# Misc Challenge: Git Forensics
# Creates a git repository where the flag was committed and then removed.
# Players must use git log, git diff, or git show to find the flag in history.
#
# Usage: bash setup.sh
# Output: challenge_repo/ (a git repository with buried history)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/challenge_repo"
FLAG="zemi{g1t_h1st0ry_n3v3r_l13s}"

# Clean up if exists
rm -rf "${REPO_DIR}"
mkdir -p "${REPO_DIR}"
cd "${REPO_DIR}"

git init
git config user.email "developer@example.com"
git config user.name "Developer"

# Commit 1: Initial project setup
cat > README.md << 'HEREDOC'
# My Awesome Project
A simple web application.
HEREDOC
cat > app.py << 'HEREDOC'
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello, World!"

if __name__ == '__main__':
    app.run(debug=True)
HEREDOC
git add -A
git commit -m "Initial commit: project setup"

# Commit 2: Add configuration (with the flag!)
cat > config.py << HEREDOC
# Application configuration
DEBUG = True
SECRET_KEY = "${FLAG}"
DATABASE_URI = "sqlite:///app.db"
HEREDOC
git add config.py
git commit -m "Add application configuration"

# Commit 3: Add requirements
cat > requirements.txt << 'HEREDOC'
flask==3.0.0
gunicorn==21.2.0
HEREDOC
git add requirements.txt
git commit -m "Add requirements.txt"

# Commit 4: Remove the secret (but it's still in history!)
cat > config.py << 'HEREDOC'
# Application configuration
import os
DEBUG = os.environ.get('DEBUG', False)
SECRET_KEY = os.environ.get('SECRET_KEY', 'change-me')
DATABASE_URI = os.environ.get('DATABASE_URI', 'sqlite:///app.db')
HEREDOC
git add config.py
git commit -m "Security fix: move secrets to environment variables"

# Commit 5: Add more features (noise)
cat > auth.py << 'HEREDOC'
def login(username, password):
    """Authenticate a user."""
    # TODO: implement proper authentication
    return username == "admin" and password == "admin"
HEREDOC
git add auth.py
git commit -m "Add authentication module"

# Commit 6: Update README
cat > README.md << 'HEREDOC'
# My Awesome Project
A simple web application built with Flask.

## Setup
1. pip install -r requirements.txt
2. Set environment variables (SECRET_KEY, DATABASE_URI)
3. python app.py
HEREDOC
git add README.md
git commit -m "Update README with setup instructions"

echo ""
echo "[+] Created git repository at ${REPO_DIR}"
echo "    Total commits: $(git rev-list --count HEAD)"
echo ""
echo "To solve:"
echo "  cd ${REPO_DIR}"
echo "  git log --all --oneline"
echo "  git log -p  # shows diffs"
echo "  git show <commit-hash>:config.py"
echo "  # Or: git log -p --all -S 'zemi{' -- '*.py'"
