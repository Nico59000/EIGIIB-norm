# E14-A2 decision precedence

For the four required component results:

1. any authoritative negative derives `deny`;
2. otherwise any `unavailable` derives `unavailable`;
3. otherwise any `held` derives `held`;
4. otherwise the result is `permit`.

This order prevents a known denial from being hidden by uncertainty while preserving unavailable and held as distinct non-positive outcomes.
