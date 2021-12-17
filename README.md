# certificate-stark
The Topos state-transition AIR program backed by the winterfell library.

* This crate can be made `no_std` compliant, by relying on the `alloc` crate instead.

**WARNING:** This is an ongoing, prototype implementation subject to changes. In particular, it has not been audited and may contain bugs and security flaws. This implementation is NOT ready for production use.


## Features

* `concurrent`: Enables multi-threading during proof generation. It implies the `std` feature.
* `std` (on by default): Enables the use of the Rust standard library

## Description

The Topos state-transition AIR program ensures a global consistency of the Topos ecosystem by means of zk-STARKs.
It verifies the consistency of transactions provided as private witness, through a set of hardcoded rules validating or rejecting them.

It internally relies on the winterfell library.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.