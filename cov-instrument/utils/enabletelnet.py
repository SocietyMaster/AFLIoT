#!/usr/bin/python
# -*- coding: utf-8 -*-
import requests
import re
from requests.auth import HTTPBasicAuth

netgear = '192.168.51.1:80'
# netgear = '127.0.0.1:53332'
session = requests.session()

url = 'http://%s/debug.htm' % netgear
resp = session.get(url, auth=HTTPBasicAuth('admin', 'admin'))
resp.encoding = 'utf-8'
sid = re.findall(r'newdebug\.cgi\?id=(\w{64})', resp.text)[0]

html = """
<form id="cf3" action="newdebug.cgi?id=e64ac170a4f9cc3dc699fb23a95a7122acedba372559244a67cf3dc59857dfb2" method="POST">
&nbsp;&nbsp;
<!--
<input type="checkbox" name="action_Enable_Telnet" value="Telnet_Enable" onclick="document.forms[3].submit();"><b> Enable Telnet</b>
<input type="hidden" name="Enable_Telnet" value="On">
<br><br>-->
&nbsp;&nbsp;
<input name="action_Mirror_Port" value="Port_mirror" onclick="document.forms[3].submit();" type="checkbox"><b> WAN Port mirror to LAN port 1</b>
<input name="WAN_port_mirror_to_LAN_port" value="Off" type="hidden">
<input name="form" value="3" type="hidden">
</form>
"""

url = 'http://%s/newdebug.cgi?id=%s' % (netgear, sid)
resp = session.post(
    url=url,
    headers={
        'Referer': 'http://%s/debug.htm' % netgear,
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    data='action_Enable_Telnet=Telnet_Enable&Enable_Telnet=On&form=3',
    auth=HTTPBasicAuth('admin', 'admin'))
