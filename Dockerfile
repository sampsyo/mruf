# We start with Ubuntu 13.10, which is the latest as of this writing.
FROM stackbrew/ubuntu:saucy
MAINTAINER Adrian Sampson <adrian@radbox.org>

# Install stuff from Ubuntu's repositories.
RUN echo "deb http://archive.ubuntu.com/ubuntu saucy main universe multiverse restricted" > /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y python python-dev python-pip

# Ridiculous dance to get a UTF-8 locale on Ubuntu.
RUN locale-gen en_US.UTF-8
RUN dpkg-reconfigure locales
ENV LC_ALL en_US.UTF-8

# Install the Gunicorn server.
RUN pip install gunicorn

# Set up the server.
EXPOSE 8118
CMD ["gunicorn", "-b", "0.0.0.0:8118", "mruf:app"]

# Add this repository to the container.
ADD . /home/mruf
WORKDIR /home/mruf

# Install the code's requirements.
RUN pip install -r requirements.txt
