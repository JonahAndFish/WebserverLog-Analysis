import os
import errno
import socket
import re

from geoip import geolite2

class Process:

#-------------------------------------------------------------------------------------------------#
#Logic for first three requirements
    #function to write all the unique IP address
    def writeUniqueIPAddress(self,uniqueIPAddressSet,filename):
        print "Writing Unique IP Address..."
        #create a file that contains the unique ip address using the name of the file uploaded by user
        #print "unique IP address"
        f = open(filename+"-unique ip", "w")
        for uniqueIPAddress in uniqueIPAddressSet:
            f.writelines(uniqueIPAddress+"\n")
    
    #function to write all the unique IP address with country and its number of hits to a file
    def writeUniqueIPAddressWithCountry(self,IPAddressList,uniqueIPAddressSet,filename):
        print "Writing Unique IP Address with country..."
        #create an array of ip address with country
        uniqueIPAddressWithCountryList = []
        #use geolite2 library to check if the unique ip address represents a country
        for key in uniqueIPAddressSet:
            match = geolite2.lookup(key)
            if match is not None:
                uniqueIPAddressWithCountryList.append(key)
        #create a dictionary to store the number of hits for each unique ip address with country. 
        IPListDic = dict()
        for key in uniqueIPAddressWithCountryList:
            IPListDic[key] = 0
        #loop the list with all IP address. Increase the count by 1 whenever the same IP address appears again
        for key in IPAddressList:
            value = IPListDic.get(key)
            if value is not None:
                value = IPListDic.get(key) + 1    
                IPListDic[key] = value

        f = open(filename+"-unique ip country", "w")
        f.writelines("IP Address, Country, No. Of Hits"+"\n")

        #write the country, hits and unique ip addresses to a file
        for key in IPListDic:
            match = geolite2.lookup(key)
            if match is not None and match.country is not None:
                lineToWrite = key + "---" + match.country + "---" + str(IPListDic.get(key))
                f.writelines(lineToWrite+"\n")
                continue
             
    #function to write all activities per IP address to its own text file
    def writeActivityPerIP(self,uniqueIPAddressSet,filename):
        print "Writing activities per Unique IP Address..."
        #create dict of key and value. key = ip address, value = list that saves all entries related to the ip address
        IPActivityDic = dict()
        passFile = open (filename)
        counter = 0
        
        #make a new directory to keep the current directory neat
        HelperClass().makeDir()
        for uniqueIPAddress in uniqueIPAddressSet:
            #create files for all unique ip address 
            f = open("./IP Address Activity/" + filename+"-"+uniqueIPAddress, "w")
            f.close
            #initialize ip address to be the key in the dict. 
            IPActivityDic[uniqueIPAddress] = []
        count = 0
        
        for logEntry in passFile.readlines():
            count = count + 1
            #cut the parsing when log entry is more than 10000 for testing purpose
            if count > 10000:
                break
            for uniqueAddress in uniqueIPAddressSet:
                if uniqueAddress in logEntry:
                    #add the activity entry to dictionary
                    IPActivityDic[uniqueAddress].append(logEntry)

        #write activity entry from dictionary to files
        for key in IPActivityDic:
            f = open("./IP Address Activity/" + filename+"-"+key, "w")
            for logEntry in IPActivityDic[key]:
                f.writelines(logEntry)
    
    
#-------------------------------------------------------------------------------------------------#
#Logic for next three requirements
    
    def checkFileInclusion(self,filename,AllRecordList):
        print "Running RFI Check..."
        f = open(filename+"-RFI", "w")
        for line in AllRecordList:
            try:
                if HelperClass().checkRFIExpression(line)==True:
                    f.writelines(line)
            except IndexError:
                #print "log file error, skipped"
                continue

        
    def checkSQLi(self,filename,AllRecordList):
        print "Running SQLi Check..."
        f = open(filename+"-SQLi", "w")
        for line in AllRecordList:
            #check if the entry contains any expressions that could be a SQLi
            try:
                if HelperClass().checkSQLiExpression(line)==True:
                    f.writelines(line)
            except IndexError:
                #print "log file error, skipped"
                continue
      
     
    def checkWebShell(self,filename,AllRecordList):
        print "Running Web Shell Check..."
        f = open(filename+"-WebShell", "w")
        for line in AllRecordList:
            #check if the entry contains any expressions that could be a SQLi
            try:
                if HelperClass().checkWebShellExpression(line)==True:
                    f.writelines(line)
            except IndexError:
                #print "log file error, skipped"
                continue
        
        

#-------------------------------------------------------------------------------------------------#
#helper functions for file processing
class HelperClass:
    
    #function to check if the entry has any expression that matches SQLi. returns true once a suspicious entry is found
    def checkSQLiExpression(self,line):
        #return true immediately once an expression that is simliar to SQLi is detected
        #change the line in the file to upper case so allow case insensitive comparison
        line = line.upper()
        #excluded inverted commas ' as it will cause too many "innocent" entries to be wrongly identified
        #excluded -- as it will cause too many "innocent" entries to be wrongly identified
        #position the most common expression on top to quicken the return speed
        #there are more possible expressions, expressions used should be tailored to the environment
        if "%27" in line:
            return True
        #weak validation as hacker can easily change to 2=2 or any comparison that returns true
        if "OR 1=1" in line:
            return True
        if "1=1--" in line:
            return True
        if "INSERT" in line:
            return True
        if "UNION" in line:
            return True
        if "CREATE" in line:
            return True
        if "DECLARE" in line:
            return True
        if "CAST" in line:
            return True
        if "EXEC" in line:
            return True
        if "DELETE" in line:
            return True


    #function to check if any webshell in the entry. returns true once a suspicious entry is found

    def checkWebShellExpression(self,line):
        line = line.upper()
        arrayLine = line.split(" ")
        statusCode = arrayLine[-4]
        #assigning the requested file to a variable
        requestedFile = arrayLine [4]
        #assigning the referrer to a variable. 
        #a request without a referrer may suggest it is a webshell.
        referrer = arrayLine[-5]
        #return true if requestedFile gets to big. it may contain shell code in the url.
        if len(requestedFile) > 500:
            return True
        #a web shell may be requrested if requestedFile ends with a file type that could be used to code web shell: rb, php, asp, py, sh etc
        if requestedFile.endswith(".PHP") or requestedFile.endswith(".RB") or requestedFile.endswith(".ASP") or requestedFile.endswith(".PY") or requestedFile.endswith(".SH") :   
            #the response code has to be successful if a web shell is called successfully.
            if statusCode == "200" :
                return True
            
        #sometimes no referrer indicates a webshell is called. However, it creates too many false positive result, so it is commented off
        #if referrer == "-" :
            #print requestedFile
            #return True
    #function to check if any RFI in the entry. returns true once a suspicious entry is found
    
    def checkRFIExpression(self,line):
        #change the line in the file to upper case so allow case insensitive comparison
        line = line.upper()
        
        #1st layer check. check if the entry contains more than one http/s record. filter out records with only one http/s
        #return false immediately if there is only 1 HTTP in the same url request string since it requires minimum 2 HTTP to carry our remote file inclusion in one request. 1 for payload while the other 1 for the legitimate host/domain name
        httpCountCheck = False
        suspiciousLine = ""
        arrayLine = line.split(" ")
        for temp in arrayLine:            
            if temp.count("HTTP") > 1:
                httpCountCheck = True
                suspiciousLine = temp
                
        if httpCountCheck == False:
            return False
        
        #get the two urls of the suspicious request in an array. remove the http:// or https://
        
        s2 = "HTTP" 
        first_index = suspiciousLine.find(s2, suspiciousLine.find(s2))
        second_index = suspiciousLine.find(s2, suspiciousLine.find(s2)+1)
        originalRequest = suspiciousLine[first_index:second_index]
        payLoad = suspiciousLine[second_index:None] 

        #remove protocol type for comparison. got to remove https before http. so the data won't corrupt
        originalRequest = originalRequest.replace('HTTPS://','')
        payLoad = payLoad.replace('HTTPS://','')
        
        originalRequest = originalRequest.replace('HTTP://','')
        payLoad = payLoad.replace('HTTP://','')
        
        
        #2nd layer check. check if http/s payload request contains a IP address. most legitimate URL referencing uses the domain/hostname name while RFI may use IP address
        
        IPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        IPAddress = re.findall( IPattern, payLoad )
        for IPTemp in IPAddress:
            #return true once ip address is found
            try:
                socket.inet_aton(IPTemp)
                return True
            except socket.error:
                continue
        
        #3rd layer check. comparison between payload parameter and domain/host name. legitimate requests usually have matching names.
        originalRequest = originalRequest.replace('WWW.','')
        payLoad = payLoad.replace('WWW.','')
        s2 = "/" 
        first_index = originalRequest.find(s2, originalRequest.find(s2))
        originalRequest = originalRequest[None:first_index]
        
        first_index = payLoad.find(s2, payLoad.find(s2))
        payLoad = payLoad[None:first_index]
        
        if originalRequest!=payLoad:
            return True
        
        
    #function to make directory to contain activites per ip address
    def makeDir(self):
        path = "./IP Address Activity"
        try:
            os.makedirs(path)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise

