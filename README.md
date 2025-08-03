# Redpanda Connection Examples

This repository provides practical examples and tests demonstrating various security-related configuration options for connecting to Redpanda. The primary focus is on showcasing how to configure and establish secure connections using SASL (SCRAM and PLAIN), TLS, and mTLS (mutual TLS).

## Purpose

The main goal of this project is to serve as a clear and concise reference for developers and operators looking to implement secure communication with Redpanda clusters. It illustrates the necessary configurations on the client side (using `kgo` for Go clients) to interact with Redpanda instances secured with different authentication and encryption mechanisms.

## Why This Is Helpful

Securing data in transit is crucial for any production system. Redpanda offers robust security features, but correctly configuring clients to leverage these features can sometimes be complex. This repository aims to simplify that process by:

- **Providing working examples:** Instead of theoretical explanations, this project offers runnable code that demonstrates how to set up secure connections.
- **Covering key security protocols:** It specifically addresses SASL (SCRAM and PLAIN for authentication) and TLS/mTLS (for encryption and mutual authentication), which are fundamental for secure Kafka-compatible environments.
- **Facilitating testing:** The `redpanda_test.go` file contains comprehensive tests that validate the connection configurations, ensuring that the examples are functional and reliable. This also provides a blueprint for users to test their own Redpanda security setups.
- **Accelerating development:** By providing ready-to-use examples, developers can quickly integrate secure Redpanda connections into their applications without extensive trial and error.

This project is an invaluable resource for understanding, implementing, and verifying secure Redpanda client configurations.


# Additional Information
- https://docs.redpanda.com/current/manage/security/authentication/
- https://docs.redpanda.com/current/manage/security/encryption/