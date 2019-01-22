# Hub performance probe
# Runs a performance/load test on a Hub server
#
FROM python:3

# derived from https://linux-tips.com/t/how-to-install-java-8-on-debian-jessie/349
RUN echo "deb http://ppa.launchpad.net/webupd8team/java/ubuntu xenial main" > /etc/apt/sources.list.d/webupd8team-java.list && echo "deb-src http://ppa.launchpad.net/webupd8team/java/ubuntu xenial main" >> /etc/apt/sources.list.d/webupd8team-java.list
RUN apt-key adv --no-tty --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys EEA14886
RUN apt-get update
# from https://askubuntu.com/questions/190582/installing-java-automatically-with-silent-option?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
RUN echo debconf shared/accepted-oracle-license-v1-1 select true | debconf-set-selections && echo debconf shared/accepted-oracle-license-v1-1 seen true | debconf-set-selections
RUN yes | apt-get install -y oracle-java8-installer
RUN java -version

# Need maven to run hub-detect on the Struts showcase sample (maven) app we use in the benchmarking
RUN apt-get install -y maven

WORKDIR /usr/src/app

COPY test_projects ./test_projects

COPY hub-detect*.jar ./

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./

# see https://blog.codeship.com/understanding-dockers-cmd-and-entrypoint-instructions/
ENTRYPOINT ["python", "hub_performance_probe.py"]
