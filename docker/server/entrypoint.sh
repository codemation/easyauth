#!/bin/bash
{
    gunicorn server:server \
        -w 1 \
        -k uvicorn.workers.UvicornWorker \
        -b 0.0.0.0:8220
}