# splunkalert
python script for generating email based splunk alerts

## How it works

I wrote this to get some added value out of free splunk. Losing alert functionality after the enterprise trial license expires dramatically reduces usefulness in a home lab splunk setup. The idea is to run this as a cronjob either on the Splunk server or any other box that can reach the API interface (http://splunk:8089) of splunk. 

As written, the script assumes authentication is needed, ie, the enterprise trial license is still active, but you can still use it by simply removing the authentication settings. See this article for guidance - https://answers.splunk.com/answers/43809/does-splunk-free-license-allow-usage-of-rest-api.html

## Instructions

Let's assume you're running splunk on an Ubuntu box and you want to run splunk-alerter.py from the same machine. Save the script and make it executable: 

    mkdir /opt/scripts/
    cp splunk-alerter.py /opt/scripts
    chmod +x splunk-alerter.py
 
 Then edit your crontab
 
     crontab -e
 
 Add a line to run the script every hour at 30 minutes past the hour: 
 
     30 * * * * /opt/scripts/splunk-alerter2.py
 
 This time range is customizable. If you want it to run at a different time interval, modify these lines in the script that determine how far back the search goes then set your cron job to match: 
 
     kwargs_oneshot = {"earliest_time": "-1h",
                          "latest_time": "now"}

 
 ## Searches
 
 I provided some very basic searches in the script. They're really just there to get a feel for how the searches need to be formatted. 
 
For example, here is a basic one that will search for a new Windows user being created. The format is a dictionary, where the key is the search description and the value is the actual search. This is important because the search description will become the email subject when the alert is triggered: 
 
     windows_user_added = {'A New User Was Created': 'search "4720   Microsoft-Windows-Security-Auditing"'}

Once the search is created, it has to be added to the "complete_search_list" list, otherwise it is not actively searched when the script is executed. 


## Alert email

The script will only send an email when an alert triggers. The if,elif, else in the SplunkOneShotSearch function is meant to ensure that even if you accidentally put a search term in that returns many results, the email itself will only contain at most 5 events. 
