FROM node:18-slim

ARG KEYSTORE_PASSWORD
ARG LDAP_ADMIN_USERNAME
ARG LDAP_ADMIN_PASSWORD
ARG LDAP_ADMIN_DN

ENV KEYSTORE_PASSWORD=$KEYSTORE_PASSWORD

ENV LDAP_ADMIN_USERNAME=$LDAP_ADMIN_USERNAME
ENV LDAP_ADMIN_PASSWORD=$LDAP_ADMIN_PASSWORD
ENV LDAP_ADMIN_DN=$LDAP_ADMIN_DN

RUN mkdir /home/scimgateway
RUN cd /home/scimgateway; npm init -y; npm install scimgateway@4.4.4


#Remove the hardcoded configs and link to the volume
RUN rm /home/scimgateway/index.js
COPY scimgateway.p12 /home/scimgateway/config/certs/scimgateway.p12

CMD ["node", "/home/scimgateway/index.js"]