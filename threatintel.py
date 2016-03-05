#!/usr/bin/env python

#Rex Petersen
#Created 3/5/16
#https://github.com/h3dg3-Wytch

#In case the README.txt was not read, this file parses through the honeypot 
#file provided. You may pass in an IP address to read, seperated by spaces then 
#tells you if you the info on it
import json
import sys
def json_loads_byteified(json_text):
    return _byteify(
        json.loads(json_text, object_hook=_byteify),
        ignore_dicts=True
    )

def _byteify(data, ignore_dicts = False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [ _byteify(item, ignore_dicts=True) for item in data ]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    # if it's anything else, return it in its original form
    return data
#If the length of the argument bundle is only 1, the user didn't pass
#in IP address, we exit
if len(sys.argv) == 1:
   print "Please enter a valid IP address"
   sys.exit()
#Each line contains valid JSON, but as a while, it isn't valid JSON value
#as there is no top-level list or object definition. 
data = []

#open the file, and then for each line in the file, add a line of JSON to 
#data
with open('honeypot.json') as file:
	for line in file:
            data.append(json.loads(line))
#further parse the payload, and then print out the connectionType of the
#parsed JSON payload
j = 0
for item in data:
    #Figure out the date
    date = data[j]['timestamp']
    dateKeys = date.keys()
    j = j + 1
    #Figure out the payload Data
    payloadData = json_loads_byteified( item['payload'])
    keys = payloadData.keys()
    #IF we find the connection they entered, we print out the 
    #the info
    i = 1
    while( i < len(sys.argv)):
         if(payloadData[keys[4]] == sys.argv[i]):
           print "Information for Victim: ", payloadData[keys[4]]
           print "Attacker IP: ", payloadData[keys[2]]
           print "Connection Type: ", payloadData[keys[3]] 
           print "Source: Honeypot"
           print "Time stamp: ",  date[dateKeys[0]] 
         break
         i += 1
