# Gitea Actions

The repository includes `.gitea/workflows/ci.yml`. On every push to `main`, on pull requests, and when started manually, it:

1. runs the unit-test suite;
2. compiles the Python sources;
3. checks the dashboard JavaScript syntax;
4. builds the portable macOS ZIP;
5. verifies that the launcher is executable, required modules are present, and report or secret paths were not packaged;
6. publishes the verified ZIP as a 14-day build artifact.

The workflow does not need repository secrets and does not upload scan reports or case evidence.

## One-time Gitea setup

Gitea Actions needs both repository Actions and an `act_runner` connected to the Gitea instance.

1. Open the repository in Gitea.
2. Go to **Settings → Actions → General** and enable repository Actions.
3. In the Gitea administration interface, create or copy a runner registration token.
4. Install `act_runner` on a dedicated runner host or container, then register it against the instance URL. Do not save the registration token in this repository.
5. Give the runner an `ubuntu-latest` label backed by a Linux container image that includes Node.js. The standard runner labels already provide this mapping.
6. Push a change or open **Actions** in the repository and run **Test and package** manually.

The job intentionally uses a Linux runner because orchestration, reporting, packaging, and most parser tests are platform-independent. The real macOS collectors still need validation on a Mac; a macOS runner should be added only when a dedicated, trusted host is available. This prevents the normal CI job from waiting indefinitely for a runner that does not exist.

If the Gitea instance is configured with `DEFAULT_ACTIONS_URL=self` instead of its normal GitHub-compatible action source, mirror `actions/checkout`, `actions/setup-python`, and `actions/upload-artifact` into the Gitea instance or update the workflow to their fully qualified mirror URLs.

The workflow currently uses `actions/upload-artifact@v3` for compatibility with older self-hosted Gitea releases. A later move to the v4 artifact backend should use a Gitea-compatible v4 action and be tested against the exact server and runner versions first.

Official references:

- [Gitea Actions quick start](https://docs.gitea.com/usage/actions/quickstart)
- [Act Runner guide](https://docs.gitea.com/next/usage/actions/act-runner)
- [Gitea Actions compatibility](https://docs.gitea.com/usage/actions/comparison)
