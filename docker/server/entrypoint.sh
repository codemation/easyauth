#!/bin/bash
{
    gunicorn server:server \
        -w $AUTH_WORKERS \
        -k uvicorn.workers.UvicornWorker \
        -b 0.0.0.0:8220
}