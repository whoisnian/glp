# glp
[![Release Status](https://github.com/whoisnian/glp/actions/workflows/release.yml/badge.svg)](https://github.com/whoisnian/glp/actions/workflows/release.yml)  
Golang limited mitm http proxy.

## example
```sh
# step.1 in terminal@1: create `devbox` container for tests
docker network create --driver bridge --internal --subnet 172.27.1.0/24 hostonly
docker run --rm -it --name devbox \
  --network hostonly \
  -e HTTP_PROXY=http://172.27.1.1:8889 \
  -e HTTPS_PROXY=http://172.27.1.1:8889 \
  alpine:3.21 sh

# step.2 in terminal@2: build and start proxy server
./build/build.sh . && ./output/glp -l 172.27.1.1:8889

# step.3 in terminal@3: copy ca certificate to `devbox` container
openssl x509 -outform pem -in ~/.mitmproxy/mitmproxy-ca.pem -out ~/.mitmproxy/glp.pem
docker cp ~/.mitmproxy/glp.pem devbox:/tmp/glp.pem

# step.4 in terminal@1: append to system ca-certificates.crt and upgrade through proxy
cat /tmp/glp.pem >> /etc/ssl/certs/ca-certificates.crt
apk update && apk upgrade && apk add git

# step.5 in terminal@1: git clone from github through proxy
git clone https://github.com/whoisnian/glp.git
```
![alpine-example](./doc/alpine-example.svg)

## implementation
![proxy.drawio.svg](./doc/proxy.drawio.svg)
