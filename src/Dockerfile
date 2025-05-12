FROM ubuntu

WORKDIR /app

COPY . .

RUN apt update -y
RUN apt install python3 -y
RUN apt install python3-flask -y
RUN apt install python3-flask-cors -y
RUN apt install grype -y

CMD ["python3","app.py"]


EXPOSE 443
