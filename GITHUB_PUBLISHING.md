# Publishing GeoTerra to GitHub

This package is prepared for source-code publication. Before pushing, create an empty repository on GitHub and copy its HTTPS or SSH URL.

From this project folder, run:

```bash
git init
git add .
git status --short
```

Inspect the staged file list. It should not include `.env`, anything under `data/` or `private_uploads/`, database files, logs, or real user documents. Then commit and connect the empty GitHub repository:

```bash
git commit -m "Prepare GeoTerra land management portal"
git branch -M main
git remote add origin YOUR_GITHUB_REPOSITORY_URL
git push -u origin main
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with the URL of the repository you created. Do not paste access tokens or passwords into source files or commit messages. GitHub may ask you to authenticate through its normal sign-in flow.

For local use, copy `.env.example` to `.env` and replace every placeholder with unique secrets before running `npm install` and `npm start`. Never commit `.env`.
