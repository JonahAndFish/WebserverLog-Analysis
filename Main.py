from optparse import OptionParser
from Process import Process,HelperClass


import socket
import re


def main():
#-------------------------------------------------------------------------------------------------#
    #ask user to upload a log file
    #allow user to choose to avoid doing unnecessary tasks
    parser = OptionParser(usage="usage: "+"-f <Log File>")
    parser.add_option('-f', dest="filedest", metavar="Log File",
                      type="string",
                      help="Specify a log file to be read")

    #allow user to have the option of storing unique address
    parser.add_option('-u', action="store_true", dest="uniqueIPAddressOption",
                      help="Specify -u to put a list of unique IP addresses to a flat file")

    #allow user to have the option of storing unique address with country and number of hits
    parser.add_option('-c', action="store_true", dest="uniqueIPAddressWithCountryOption",
                      help="Specify -c to put a list of unique IP addresses with country and number of hits to a flat file")

    #allow user to have the option of storing activities per IP Address
    parser.add_option('-a', action="store_true", dest="uniqueIPActivityOption",
                      help="Specify -a to list all activity per IP address to individual flat files per IP")

    #allow user to have the option of storing entries that could possibly be infected with SQLi
    parser.add_option('-s', action="store_true", dest="SQLiOption",
                      help="Specify -s to list all possible SQL injection entries to a flat file")

    #allow user to have the option of storing entries that could possibly be infected with file inclusion
    parser.add_option('--fi', action="store_true", dest="fileInclusionOption",
                      help="Specify --fi to list all possible file inclusion entries to a flat file")

    #allow user to have the option of storing entries that could possibly be infected with web shell
    parser.add_option('--ws', action="store_true", dest="webShellOption",
                      help="Specify --ws to list all possible web shell entries to a flat file")


    (options, args) = parser.parse_args()

    #instruct user to input log file if no file is uploaded
    if (options.filedest==None):
        print parser.usage
        #exit the program if no file is uploaded
        exit(0)
    else:
        filename = options.filedest


#-------------------------------------------------------------------------------------------------#
#Process the log file uploaded. 
    passFile = open (filename)
    #create a list to contain all the ipaddress
    IPAddressList = []
    uniqueIPAddressList = []
    AllRecordList = []
    fileSize = 0
    
    print "reading the file"
    
    #read the file uploaded line by line and save it to an array    
    for line in passFile.readlines():
        fileSize = fileSize + 1
        #retrieve the ipaddress and save it in the IPAddressList created earlier
        try:
            #retrieve patterns that match ip addresses
            IPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            IPAddress = re.findall( IPattern, line )
            AllRecordList.append(line)
            for IPTemp in IPAddress:
                #double validation to ensure the ip address is valid
                try:
                    socket.inet_aton(IPTemp)
                    IPAddressList.append(IPTemp)
                except socket.error:
                    continue
        except IndexError:
            continue

#converting list to set which retrieves the unique ip address 
    uniqueIPAddressSet = set(IPAddressList)

#-------------------------------------------------------------------------------------------------#
#process the first three requirements
    #print "Writing Unique IP Address"
    if (options.uniqueIPAddressOption==True):
        Process().writeUniqueIPAddress(uniqueIPAddressSet,filename)
        
    #print "Writing Unique IP Address with Country"
    if (options.uniqueIPAddressWithCountryOption==True):
        Process().writeUniqueIPAddressWithCountry(IPAddressList,uniqueIPAddressSet,filename)
        
    #print "Writing Unique IP Activities"
    if (options.uniqueIPActivityOption==True):
        Process().writeActivityPerIP(uniqueIPAddressSet,filename)
        
#-------------------------------------------------------------------------------------------------#
# process the next three requirements
# another option is to loop through the array just once and perform all three operations instead of looping it three times to perform its own operation. it will improve the performance. however, it will require many permuations. eg, true true true, true false true, false false true. to keep codes simple and readable, i didn't implement that. the improvement is not very significant unless the log file uploaded is huge.

    if (options.fileInclusionOption==True ):
        Process().checkFileInclusion(filename,AllRecordList)

    if (options.SQLiOption==True): 
        Process().checkSQLi(filename,AllRecordList)

    if (options.webShellOption==True):
        Process().checkWebShell(filename,AllRecordList)  

#function to write all the unique IP address to a file
if __name__ == "__main__":
    main()