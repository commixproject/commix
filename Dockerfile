FROM python:2.7-alpine
LABEL maintainer="Mostafa Hussein <mostafa.hussein91@gmail.com>"
ADD ./ /home/commix
WORKDIR /home/commix
RUN adduser -D commix -H -h /home/commix && chown commix:commix /home/commix -R
USER commix
ENTRYPOINT ["python", "commix.py"]
CMD ["-h"]
