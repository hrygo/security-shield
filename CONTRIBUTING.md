# Contributing to Security Shield

Thank you for your interest in contributing! All kinds of contributions are welcome: bug reports, feature requests, code, documentation, and translations.

## Code of Conduct

This project follows a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Report Bugs

- Search [existing issues](https://github.com/hrygo/security-shield/issues) to avoid duplicates
- Open a [new issue](https://github.com/hrygo/security-shield/issues/new) with the bug report template
- Include: reproduction steps, expected vs actual behavior, plugin version, and OpenClaw version

### Suggest Features

- Open a [new issue](https://github.com/hrygo/security-shield/issues/new) with the feature request template
- Explain the problem you're trying to solve and why it matters
- Propose a solution if you have one in mind

### Submit Code

1. Fork the repository
2. Create a branch (`git checkout -b feat/your_feature` or `fix/your_fix`)
3. Make your changes
4. Run type checks: `npm run build`
5. Commit using [Conventional Commits](https://www.conventionalcommits.org/)
6. Push and open a Pull Request

### Translation

To improve the Chinese translation (`README.zh-CN.md`):

1. Edit `README.zh-CN.md`
2. Ensure structure matches `README.md`
3. Submit a PR describing the translation changes

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Follow the existing code style and conventions
- Add or update tests for new features
- Update documentation if behavior changes
- Use the provided [PR template](.github/PULL_REQUEST_TEMPLATE.md)

## Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

Examples:
feat(detectors): add morse code detection
fix(state-manager): restore lock state after restart
docs(readme): add ROI decision matrix
chore(ci): add typecheck workflow
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`, `perf`

## Development Setup

```bash
git clone https://github.com/hrygo/security-shield.git
cd security-shield
npm install
npm run build
```

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
