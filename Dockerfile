# iocflow — the full IOC lifecycle as a container.
#
#   docker build -t iocflow .
#   echo "c2 at 185.220.101.5" | docker run -i --rm iocflow extract --json
#   docker run --rm -e IOCFLOW_VT_API_KEY=… iocflow enrich "…report…"
#
# Installs every extra so any subcommand works out of the box. The image is the
# CLI: ENTRYPOINT is `iocflow`, so args after the image name are its arguments.
FROM python:3.12-slim AS build

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# Build a wheel and install it (with all extras) into an isolated prefix we can
# copy into the slim runtime stage.
RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /tmp/dist \
    && pip install --no-cache-dir --prefix=/install "$(echo /tmp/dist/*.whl)[enrich,ai,hunt,block,sources,stix,misp,mitre,agent]"

FROM python:3.12-slim

# Non-root by default — the container only needs to read text and call out.
RUN useradd --create-home --uid 10001 ioc
COPY --from=build /install /usr/local
USER ioc
WORKDIR /home/ioc

ENTRYPOINT ["iocflow"]
CMD ["--help"]
