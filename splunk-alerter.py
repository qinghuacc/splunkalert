#!/usr/bin/env python

import splunklib.client as client
import splunklib.results as results
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
import sys
from datetime import datetime 
import time

# Need splunk sdk for this to work!
# pip install splunk-sdk

HOST = "splunk.example.com"
PORT = 8089
USERNAME = "admin"
PASSWORD = "changeme"

# Create a Service instance and log in 
service = client.connect(
    host=HOST,
    port=PORT,
    username=USERNAME,
    password=PASSWORD)

############################################################################
# Search section
# Each search is defined as a dictionary, where k is the description of the
# search and v is the actual search, then all of the searches are added to a 
# list called complete_search_list
############################################################################

# The interesting searches we'd like to get alerted on: 
# Windows: 
windows_user_added_to_local_admins = {'A user has been added to the Administrators group': 'search "4732	Microsoft-Windows-Security-Auditing" "Group Name:  Administrators"'}
windows_user_added = {'A New User Was Created': 'search "4720	Microsoft-Windows-Security-Auditing"'}
windows_domain_admin_added = {'A User Was Added to Domain Admin Group' : 'search EventID=4728 "A member was added to a security-enabled global group." "Domain Admins"'}
windows_cmd_from_services = {'cmd.exe Spawned from services.exe' : 'search Image:*\\cmd.exe  OR Image:*\\regedit.exe OR Image:*\\powershell.exe AND ParentImage:*\\services.exe'}
windows_psremote_activity = {'PS-Remote Activity Detected' : 'search Image:*\\wsmprovhost.exe AND ParentImage:*\\svchost.exe'}
windows_CACTUSTORCH = {'Shellcode inject via CACTUSTORCH' : 'search host="10.0.0.76" LogType=Microsoft-Windows-Sysmon/Operational | transaction  maxspan=1m maxevents=4 | search CommandLine:*\\WScript.exe AND ParentImage:*\\explorer.exe AND "CreateRemoteThread detected" '}
# Microsoft DNS Debug Logs:
dns_suspicious_tld_lookup = {'A Suspicious TLD Was Queried' : 'search source=MSDNS_Logs "(2)tk(0)" OR "(3)top(0)" OR "(2)ru(0)" OR "(2)cn(0)"'}
# Sophos: 
utm_ssl_vpn_connection_established = {'A new SSL VPN Connection Has Been Established': 'search sys="SecureNet" sub="vpn" event="Connection started" variant="ssl"'}
# Snort on PFSense
# Saving this search for now but it's not configured to send emails yet. 
snort_alert_triggered = {'A snort signature fired on PFSense':'search source="pfsense" sourcetype="syslog" "snort\[*\]: \[*\]"'}

# List of all the searches 
complete_search_list = [windows_psremote_activity, 
windows_cmd_from_services,
dns_suspicious_tld_lookup,
windows_user_added_to_local_admins,
windows_user_added,
windows_domain_admin_added,
windows_CACTUSTORCH,
utm_ssl_vpn_connection_established]  


# Lifted this function from oneshot.py in SDK. Used to 
# clean up search results. Changed it so it
# returns results in a list instead of printing them:  
def search_results_list(response):
    results_list = []
    reader = results.ResultsReader(response)
    for result in reader:
        if isinstance(result, dict):
            results_list.append(result)
    return results_list     
        
        
# Send an email with the search results:   
def sendScanStartEmail(search_results,search_subject):
    day = time.strftime("%Y%m%d_")
    clock = time.strftime("%I%M%S")
    timestamp = day+clock
    # create message object
    msg = MIMEMultipart()
    # fill in all the normal email parts
    msg['Subject'] = "Splunk Alert!: " + search_subject
    msg['From'] = ''
    msg['To'] = ''
    SERVER = ''
    gmail_user = ''
    gmail_password = ''
    body = ""
    body += search_results
    msg.attach(MIMEText(body))
    server = smtplib.SMTP_SSL(SERVER)
    server.ehlo()
    server.login(gmail_user , gmail_password)
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()            
            
# Runs a oneshot search and then formats the data for emailing: 
def SplunkOneshotSearch(custom_search):
    returned_data = ''
    kwargs_oneshot = {"earliest_time": "-1h",
                      "latest_time": "now"}
    for k,v in custom_search.iteritems():
        search_subject = k
        custom_search = v
    oneshotsearch_results = service.jobs.oneshot(custom_search, **kwargs_oneshot)
    search_results = search_results_list(oneshotsearch_results)
    if search_results != None:
        if len(search_results) == 1:
            returned_data += "This search returned " + str(len(search_results)) + " interesting result : " + custom_search + '\n\n'
            returned_data += "Here is the interesting log:\n\n"
            for logs in search_results:
                returned_data += logs['_raw'] + '\n'
            return returned_data    
        elif len(search_results) > 5:
            returned_data += "This search returned " + str(len(search_results)) + " interesting results : " + custom_search + '\n\n'
            returned_data += "Here are the first 5 results:\n\n"
            for logs in search_results[:5]:
                returned_data += logs['_raw'] + '\n'
            return returned_data
        elif len(search_results) > 1 <= 5:
            returned_data += "This search returned " + str(len(search_results)) + " interesting results : " + custom_search + '\n\n'
            returned_data += "Here are the results:\n\n"
            for logs in search_results[:5]:
                returned_data += logs['_raw'] + '\n'
            return returned_data        
        else:
            return None
    else:
        return None

# Iterates through the list of search dictionaries and emails if 
# The search returns something good:
def SplunkSearchandAlert(search_list):
    for searches in search_list:
        what_im_searching = searches
        search_test = SplunkOneshotSearch(what_im_searching)
        for k,v in what_im_searching.iteritems():
            search_subject = k
        if search_test != None: 
            sendScanStartEmail(search_test,search_subject)
            
def main():  
    SplunkSearchandAlert(complete_search_list)
    

if __name__ == "__main__":
    main()




