import os

# Create requirements.txt
with open('requirements.txt', 'w') as f:
    f.write("requests>=2.28.0\n")

# Create .gitignore
gitignore_content = """# Results
Result/
results/
*.json

# Python
__pycache__/
*.pyc
*.pyo

# Environment
.env
.venv

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db
"""

with open('.gitignore', 'w') as f:
    f.write(gitignore_content)

# Create Dockerfile
dockerfile_content = """FROM python:3.9-alpine

LABEL name="VulnScanX"
LABEL version="2.1.0"
LABEL description="Advanced Security Scanner"

RUN apk add --no-cache git

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

VOLUME ["/app/Result"]

ENTRYPOINT ["python", "vulnscanx.py"]
CMD ["--help"]
"""

with open('Dockerfile', 'w') as f:
    f.write(dockerfile_content)

print("All files created successfully!")
print("✅ requirements.txt")
print("✅ .gitignore") 
print("✅ Dockerfile")