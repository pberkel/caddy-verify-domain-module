# Verify Domain module for Caddy v2

This module provides a simple domain validation mechanism that can be used in conjunction with [on-demand-tls](https://caddyserver.com/docs/caddyfile/options#on-demand-tls).
It's primary goal is implementing basic security mechanisms to prevents abuse of Caddy's Automatic HTTPS functionality when accepting / upgrading all incoming requests to HTTPS.

A simple configuration example:

```
{
    on_demand_tls {
        ask http://localhost/ask
    }
    order verify_domain last
}

http:// {
    verify_domain {
        ask http://localhost/ask
    }
}

https:// {
	tls {
		on_demand
	}
}
```

When Caddy makes a request to the defined `on_demand_tls.ask` URL, this module intercepts and verifies value of query string parameter `domain` ensuring:
- it is not an IP address,
- is it DNS resolvable,
- it does not resolve to a loopback or private IP address,
- it resolves to the current Caddy server address (by making a simple HTTP challenge request)
