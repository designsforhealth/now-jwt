# now-jwt

Authentication and authorization functions for validating JWTs in serverless functions deployed on Vercel (formerly Zeit Now)

## Release Management

This project uses [`standard-version`](https://github.com/conventional-changelog/standard-version) for
consistent releases with managed changelogs.

1. `yarn run release` to run `standard-version` and release a new version.

2. `yarn run publish-release` to push commits and publish to GitHub NPM repository.

3. `yarn run github-release` to create new release in GitHub with change log.
    - Note: Be sure to configure a token in your environment first https://www.npmjs.com/package/conventional-github-releaser#setup-token-for-cli
