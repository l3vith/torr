# TODO

## High Priority
- [ ] Remove all `.unwrap()` and replace with safer error handling
- [ ] Add better error parsing and structured error types
- [ ] Add tracker request retry with backoff and max attempts
- [ ] Add timeouts for UDP and HTTP requests
- [ ] Add logging (info, warn, error) instead of `println!`

## Medium Priority
- [ ] Parse both tracker list and single tracker (support fallback)
- [ ] Add support for multiple tracker types (HTTP, HTTPS, UDP)
- [ ] Separate tracker logic into dedicated module (`tracker.rs`)
- [ ] Write integration tests for tracker responses
- [ ] Implement peer list decoding validation (size, alignment)

## Low Priority
- [ ] Reformat codebase and introduce idiomatic structs for peer/tracker state
- [ ] Introduce support for DHT
- [ ] Add CLI flags for configuration (e.g. `--no-dht`, `--port`, `--trackers`)
- [ ] Implement simple logging to file (for debugging tracker exchange)
- [ ] Refactor `main()` to a clean async workflow function

## Optional / Future
- [ ] Add support for IPv6 peers
- [ ] Implement magnet link parsing
- [ ] Cache tracker responses to reduce duplicate announces
- [ ] Build a bootstrapped GUI in GPUI
