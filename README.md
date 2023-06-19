# nessus_wazuh
nessus wazuh integration

# rules
```
<group name="nessus,network_scan">  
    <!-- Low Risk -->  
    <rule id="200401" level="3">  
        <decoded_as>json</decoded_as>  
        <field name="nessus_host">\.+</field>  
        <field name="nessus_port">\.+</field>  
        <field name="nessus_risk">Low</field>  
        <description>Nessus: Low Risk Network Vulnerability - Host $(nmap_host)</description>  
        <options>no_full_log</options>  
    </rule>  
  
    <!-- Medium Risk -->  
    <rule id="200402" level="5">  
        <decoded_as>json</decoded_as>  
        <field name="nessus_host">\.+</field>  
        <field name="nessus_port">\.+</field>  
        <field name="nessus_risk">Medium</field>  
        <description>Nessus: Medium Risk Network Vulnerability - Host $(nmap_host)</description>  
        <options>no_full_log</options>  
    </rule>  
  
    <!-- High Risk -->  
    <rule id="200403" level="7">  
        <decoded_as>json</decoded_as>  
        <field name="nessus_host">\.+</field>  
        <field name="nessus_port">\.+</field>  
        <field name="nessus_risk">High</field>  
        <description>Nessus: High Risk Network Vulnerability - Host $(nmap_host)</description>  
        <options>no_full_log</options>  
    </rule>  
  
    <!-- Critical Risk -->  
    <rule id="200404" level="10">  
        <decoded_as>json</decoded_as>  
        <field name="nessus_host">\.+</field>  
        <field name="nessus_port">\.+</field>  
        <field name="nessus_risk">Critical</field>  
        <description>Nessus: Critical Risk Network Vulnerability - Host $(nmap_host)</description>  
        <options>no_full_log</options>  
    </rule>  
</group>  

```
