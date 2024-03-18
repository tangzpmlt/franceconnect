FROM node:18

WORKDIR /usr/src/app

# Install mkcert and move the generated certificates to the certs directory
RUN apt-get update && \
    apt-get install -y wget libnss3-tools && \
    wget -O mkcert https://github.com/FiloSottile/mkcert/releases/download/v1.4.3/mkcert-v1.4.3-linux-amd64 && \
    chmod +x mkcert && \
    ./mkcert -install && \
    ./mkcert fs.tpommellet.docker.dev-franceconnect.fr && \
    mkdir -p /usr/src/app/certs && \
    mv fs.tpommellet.docker.dev-franceconnect.fr-key.pem /usr/src/app/certs && \
    mv fs.tpommellet.docker.dev-franceconnect.fr.pem /usr/src/app/certs

COPY . .

RUN npm install

# Make port 443 available to the world outside this container
EXPOSE 443

CMD [ "npm", "run", "start:dev" ]