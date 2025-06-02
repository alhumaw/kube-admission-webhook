FROM ubuntu

WORKDIR /app

COPY . .

RUN apt update -y
RUN apt install python3 -y
RUN apt install python3-flask -y
RUN apt install python3-flask-cors -y
#RUN apt install grype -y
#For Debian and Ubuntu distro
RUN curl -sSFL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

CMD ["python3","app.py"]


EXPOSE 443
