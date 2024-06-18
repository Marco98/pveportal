FROM scratch

ENTRYPOINT ["/pveportal"]
CMD ["-c", "/config/pveportal.yaml"]

COPY res/pveportal.yaml /config/pveportal.yaml
COPY pveportal /pveportal
