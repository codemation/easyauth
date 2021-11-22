# this is our first build stage, it will not persist in the final image
FROM ubuntu as intermediate

# install git
RUN apt-get update
RUN apt-get install -y git

RUN git clone https://github.com/codemation/easyauth.git

FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8
# copy the repository form the previous image

RUN mkdir -p /root/app

COPY --from=intermediate /easyauth/docker/server /root/app/easyauth

WORKDIR /root/app/easyauth

RUN echo "adding requirements"
RUN pip3 install -U -r requirements.txt
RUN pip3 install -U pydbantic[sqlite]
RUN pip3 install -U pydbantic[mysql]
RUN pip3 install -U pydbantic[postgres]

EXPOSE 8220

# TODO - add startup.sh to each REPO - will run from cloned folder
CMD ["./entrypoint.sh"]