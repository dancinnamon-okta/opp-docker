FROM redhat/ubi9

ARG OKTA_ORG_TYPE
ARG OKTA_ORG
ENV OKTA_ORG=$OKTA_ORG
ENV OKTA_ORG_TYPE=$OKTA_ORG_TYPE

ADD . /src
RUN echo "https://${OKTA_ORG}-admin.${OKTA_ORG_TYPE}.com/artifacts/OPP/02.00.15/OktaProvisioningAgent-02.00.15-5ccfa6b.x86_64.rpm"
ADD "https://${OKTA_ORG}-admin.${OKTA_ORG_TYPE}.com/artifacts/OPP/02.00.15/OktaProvisioningAgent-02.00.15-5ccfa6b.x86_64.rpm" /src
RUN cd /src; yum -y localinstall OktaProvisioningAgent-02.00.15-5ccfa6b.x86_64.rpm
RUN cp /src/configure_agent.sh /opt/OktaProvisioningAgent/configure_agent.sh
RUN /opt/OktaProvisioningAgent/configure_agent.sh
RUN chmod 777 /src/OktaProvisioningAgentForeground; cp /src/OktaProvisioningAgentForeground /opt/OktaProvisioningAgent

CMD ["/opt/OktaProvisioningAgent/OktaProvisioningAgentForeground"]
