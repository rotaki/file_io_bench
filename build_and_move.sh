cargo build --release --bin io_bench --features "preadpwrite_sync"
mv ./target/release/io_bench ./preadpwrite_sync
cargo build --release --bin io_bench --features "iouring_sync"
mv ./target/release/io_bench ./iouring_sync
cargo build --release --bin io_bench --features "iouring_async"
mv ./target/release/io_bench ./iouring_async