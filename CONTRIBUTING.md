# Contributing

1. Branch from `dev`, not `main`.
2. Run `ctest —output-on-failure` from `build/` before every commit —
   it runs the crypto test and all 8 adversarial attacks in one shot,
   and every one of them must pass before you push.
3. Keep commits small and focused on one change each.
4. Open a PR from `dev` into `main` when a batch of work is ready.
