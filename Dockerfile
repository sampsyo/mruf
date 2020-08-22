FROM alpine
MAINTAINER Adrian Sampson <adrian@radbox.org>

# Install Python, pip, and git.
RUN apk add --update py3-pip git \
    && rm -rf /var/cache/apk/*

# Install the Gunicorn server.
RUN pip3 install gunicorn

# Get the source code.
ADD . mruf
WORKDIR mruf

# Install the code's requirements.
RUN pip3 install -r requirements.txt

# Set up the server.
EXPOSE 8118
CMD ["gunicorn", "--bind", "0.0.0.0:80", \
     "--workers", "4", \
     "--forwarded-allow-ips", "*", \
     "mruf:app"]

# Use configuration from a volume.
ENV MRUF_CFG=/data/mruf.site.cfg
