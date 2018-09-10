FROM python:alpine

# build the documentation
WORKDIR /usr/src/app
COPY ./requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN mkdir -p build/html \
    && sphinx-build -b html ./source ./build/html

# serve the documentation
EXPOSE 8000
ENTRYPOINT ["sphinx-serve"]
CMD ["-b", "build", "-h", "0.0.0.0", "-p", "8000"]
