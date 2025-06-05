# wbor-serverless-functions

On DigitalOcean's functions platform.

Imposed limits:

- Up to 10 namespaces. Namespaces have the following limits:
  - Up to 120 concurrent functions.
  - Up to 600 invocations per minute.
  - Up to 256 KB of logs per invocation.
  - Up to 3 days of log retention.
- Functions have the following limits:
  - The maximum timeout is 15 minutes. This includes initialization and function execution.
  - The maximum size of input parameters is 1 MB.
  - The maximum size of result responses is 1 MB.
  - The maximum size of the built function is 48 MB.
  - The maximum build time for remote builds is 2 minutes.
  - Memory is limited from 128 MB – 1 GB, defaulting to 256 MB.
- Does not support PostgreSQL connection pools.

Note about activation logs: the only work for manually activated functions. For web activated functions, the activation logs are not available.
