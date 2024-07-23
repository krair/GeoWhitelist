FROM python:3.12-alpine

COPY ./requirements.txt /

RUN pip install -r /requirements.txt

COPY ./src/geowhitelist.py /app/

COPY ./config /app/config/

RUN adduser -D -H -u 3737 python python; \
    chown -R python:python /app; \
    chmod -R 750 /app; \
    chmod 640 /app/config/*

USER python

EXPOSE 9500

WORKDIR /app

ENTRYPOINT ["python3"]

CMD ["/usr/local/bin/uvicorn","--port","9500","--host","0.0.0.0","geowhitelist:app"]
