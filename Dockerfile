FROM python:3.10-alpine

RUN pip install redis aiohttp starlette uvicorn

COPY ./GeoWhitelist.py /app/

COPY ./config /app/config/

RUN adduser -D -H -u 3737 python python; \
    chown -R python:python /app; \
    chmod -R 750 /app; \
    chmod 640 /app/config/*

USER python

EXPOSE 9500

WORKDIR /app

ENTRYPOINT ["python3"]

CMD ["/usr/local/bin/uvicorn","--port","9500","--host","0.0.0.0","GeoWhitelist:app"]
