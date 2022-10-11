#!/bin/bash

# This script prompts the user for various scripts needed by the Provisioning Agent
# service. It populates a conf file.

### DAN C - ADDITION FOR SILENT INSTALL VIA DOCKER ###
subdomain="https://$OKTA_ORG.$OKTA_ORG_TYPE.com"
enableProxy=n

if [[ "$(id -u)" != "0" ]]; then
    echo -e "\nERROR: Please switch to root or use sudo to run this script\n"
    exit 1
fi

AgentInstallPrefix=$(rpm -q --queryformat '%{INSTPREFIXES}\n' OktaProvisioningAgent|tail -1)
. $AgentInstallPrefix/defs.sh

environment=PROD

if [[ $# >=2 ]] ; then
    if [[ $1 == '-d' ]] ; then
        environment=DEV
    fi
fi

echo -e "\nWelcome to the Okta Provisioning Agent configuration script. This needs to be run "
echo -e "once after the installation to populate required application settings.\n"
while [[ -z $subdomain ]] ; do
    echo "Enter the URL of your org. For example: https://mycompany.okta.com"
    read subdomain
done

while [[ $enableProxy != "y" && $enableProxy != "n" ]]; do
    echo
    read -p "Enable proxy (y/n)? [n]: " enableProxy

    if [[ -z $enableProxy ]]; then
        enableProxy="n"
    fi

    enableProxy=$(echo "$enableProxy" | tr '[:upper:]' '[:lower:]')
done

proxyUrl=" "
proxyUser=" "
proxyPass=" "
proxyEnabled="false"

if [[ $enableProxy == "y" ]] ; then

    proxyEnabled="true"

    unset proxyUrl

    while [[ -z $proxyUrl ]]; do
        echo "Enter the URL of the proxy server. For example: http://local.proxy:8888"
        read proxyUrl
    done

    echo
    read -p "Enter proxy username (optional): " proxyUser

    if [[ -z $proxyUser ]]; then
        proxyUser=" "
    fi

    unset proxyPass
    proxyPass=
    echo
    echo -n "Enter proxy password (optional): " 1>&2
    while IFS= read -r -n1 -s char; do
      case "$( echo -n "$char" | od -An -tx1 )" in
      '') break ;;   # EOL
      ' 08'|' 7f')  # backspace or delete
          if [ -n "$proxyPass" ]; then
            proxyPass="$( echo "$proxyPass" | sed 's/.$//' )"
            echo -n $'\b \b' 1>&2
          fi
          ;;
      *)  proxyPass="$proxyPass$char"
          echo -n '*' 1>&2
          ;;
      esac
    done
    echo

    if [[ -z $proxyPass ]]; then
        proxyPass=" "
    fi
fi

installprefix=$(rpm -q --queryformat '%{INSTPREFIXES}\n' OktaProvisioningAgent|tail -1)
ConfigFile=$installprefix/conf/OktaProvisioningAgent.conf

echo "Configuring Okta Provisioning agent"
$JAVA -Dagent_home=$installprefix -jar $installprefix/bin/OktaProvisioningAgent.jar \
-mode register \
-env $environment \
-subdomain $subdomain \
-configFilePath $ConfigFile \
-noInstance true \
-proxyEnabled "$proxyEnabled" \
-proxyUrl "$proxyUrl" \
-proxyUser "$proxyUser" \
-proxyPassword "$proxyPass"

if [[ $? == 0 ]] && [[ -r $ConfigFile ]] ; then
    # since we run this script as root, the initial logs files will be created as root
    # need to make sure the actual provisioningagent user can r/w to those log files
    chown -R provisioningagent:provisioningagent $installprefix/logs
    chown -R provisioningagent:provisioningagent $installprefix/conf

    echo -e "\nConfiguration successful.\n"
    echo "Service can now be started by typing"
    echo "service OktaProvisioningAgent start"
    echo -e "as root.\n"
    exit 0
else
    echo -e "\nERROR: configuration of Okta Provisioning Agent Failed."
    exit 1
fi
