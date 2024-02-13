FROM node:18-slim

ARG KEYSTORE_PASSWORD
ENV KEYSTORE_PASSWORD=$KEYSTORE_PASSWORD

RUN mkdir /home/scimgateway
RUN cd /home/scimgateway; npm init -y; npm install scimgateway@4.4.4


#Remove the hardcoded configs and link to the volume
RUN rm /home/scimgateway/index.js; ln -s /config/index.js /home/scimgateway/index.js
RUN rm /home/scimgateway/config/plugin-loki.json; ln -s /config/plugin-loki.json /home/scimgateway/config/plugin-loki.json
RUN rm /home/scimgateway/config/plugin-ldap.json; ln -s /config/plugin-ldap.json /home/scimgateway/config/plugin-ldap.json
RUN rm /home/scimgateway/config/plugin-mssql.json; ln -s /config/plugin-mssql.json /home/scimgateway/config/plugin-mssql.json
COPY scimgateway.p12 /home/scimgateway/config/certs/scimgateway.p12

CMD ["node", "/home/scimgateway/index.js"]