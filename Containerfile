FROM scratch

LABEL org.opencontainers.image.source https://github.com/Marco98/pveportal
ENTRYPOINT ["/pveportal"]
CMD ["-c", "/config/pveportal.yaml"]

COPY res/pveportal.yaml /config/pveportal.yaml
COPY pveportal /pveportal
