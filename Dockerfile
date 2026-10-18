FROM rust:1.98.1-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY fixtures ./fixtures
COPY examples ./examples
RUN cargo build --locked --release -p r3kj4-cli

FROM build AS test-build
RUN cargo test --locked -p r3kj4-browser --test runtime --no-run \
    && find target/debug/deps -maxdepth 1 -type f -name 'runtime-*' -executable -exec cp '{}' /usr/local/bin/runtime-tests ';'

FROM debian:bookworm-slim AS browser-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates chromium chromium-sandbox fonts-liberation \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin r3kj4 \
    && mkdir /data && chown r3kj4:r3kj4 /data
ENV CHROME_PATH=/usr/bin/chromium
WORKDIR /data
USER r3kj4

FROM browser-base AS test
COPY --from=test-build /usr/local/bin/runtime-tests /usr/local/bin/runtime-tests
CMD ["runtime-tests", "--ignored", "--nocapture", "--test-threads=1"]

FROM browser-base AS runtime
COPY --from=build /app/target/release/r3kj4 /usr/local/bin/r3kj4
ENTRYPOINT ["r3kj4"]
CMD ["--help"]
