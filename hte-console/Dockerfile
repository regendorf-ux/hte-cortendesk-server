# HTE: the hte-console image. The binary is built by .github/workflows/hte-console.yml (static musl, like the
# server image) and copied in; this file never compiles anything.
FROM alpine:3.20
COPY bin/amd64/hte-console /usr/local/bin/hte-console
RUN chmod +x /usr/local/bin/hte-console
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
    CMD wget -q -O /dev/null "http://127.0.0.1:8080/__hte-console/health" || exit 1
ENTRYPOINT ["/usr/local/bin/hte-console"]
CMD ["serve"]
