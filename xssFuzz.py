#from request_parser import reqParser
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import requests
from colorama import Fore, init
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse
from optparse import OptionParser
import re
import time


warnings.simplefilter('ignore', InsecureRequestWarning)
init(autoreset=True)


def printBanner():
        #print(1)
        print(Fore.GREEN + '''
     _  _ ____ ____ ____ _  _ ___  ___  
      \\/  [__  [__  |___ |  |   /    /  
     _/\\_ ___] ___] |    |__|  /__  /__ 
      # xssFuzzer by Asperis Security
                                   
        ''')

def printV(str,verbose=False):
        '''
        Objective: Handling verbose with ease! When you want to print something, just call this function. It will handle the rest
        '''
        if verbose:
                print(str)

def saveOutput(str,filename=None,verbose=None):
        '''
        Save the data to a file.
        str: The string  needs to be saved
        filename: The filename in which the data should be saved
        '''
        if filename:
                try:
                    with open(filename,'a') as file:
                            printV(Fore.GREEN + f"[+] Data Saved in {filename}",verbose=verbose)
                            file.write(str + '\n')
                            return True
                except PermissionError:
                        print("Error saving: " + str)
                except Exception as e:
                        print(e)
                
def readFile(filename,read=False):
        '''
        Read file from any filename
        read= True: It will return  the data as string
        read=False: It will return the data as list
        '''
        if not read:
            with open(filename,'r') as file:
                    return file.readlines()
            
        with open(filename,'r') as file:
                    return file.read()
        

def sendRequest(url,headers=None,raw=None):
        '''
        Sends request to the given url
        '''
        #print(headers)
        verify=True
        count = 0
        while True:
               if count == 3:
                      print(Fore.RED + "[-] Some Error Happened")
                      break
               try:
                    if headers:
                    #print(headers)
                    #print(url)
                        response = requests.get(url,headers=headers,verify=verify)
                        #print(response.status_code)
                        if response.status_code == 403:
                           print(Fore.RED + "[-] Request Denied!")
                        if raw:
                               return response
                        return response.text
                    else:
                        response = requests.get(url,verify=verify)
                        #print(response.status_code)
                        if raw:
                               return response
                        return response.text
               except ConnectionAbortedError:
                      count +=1
                      continue
               except Exception as e:
                      count +=1
                      printV(Fore.GREEN + f"Error {e} Trying Again")
                      verify = False

def parseParam(str):
        '''
        Helps to parse parameters given in the cli argument with --param flag
        '''
        if ',' in str:
                return str.strip().split(',')
        return str
        

def replace(param_name,value,url):
    '''
    replace the parameter_name's content with the given value and return the url
    '''
    #print(re.sub(f"{param_name}=([^&]+)",f"{param_name}={value}",url))
    return re.sub(f"{param_name}=([^&]+)",f"{param_name}={value}",url)

def getParameters(url):
        parsed_url = urlparse(url).query
        regex_pattern = r"(?<=\?|\&)[^=&]+"
        parameters = re.findall(regex_pattern, url)
        return parameters

def testParam(parameters,danger_input,url,headers=None):
        '''
        This function checks if the danger_input is reflecting in the response by appending them to the given parameters
        '''
        final_output = {"url":url,"parameters":[]}
        if parameters:
                params = parseParam(parameters) # Prase the given parameters
                #print(Fore.GREEN + f"[+] Testing Parameters:{params}")
        else:
                params = getParameters(url) # Parse all parameters
        #print(params)
        if type(params) == type([]): #If the Parameters are in list
                #print(params)
                print(Fore.GREEN + f"[+] Testing Parameters:{[x for x in params]}")
                for param in params:
                        #print(param)
                        final_url = replace(param,danger_input,url)
                        #print(final_url) #works
                        #print(headers) works
                        response = sendRequest(final_url,headers=headers)
                        if danger_input in response:
                                print(Fore.BLUE + f"[+] Parameter {param} not handling dangerous characters properly!")
                                final_output['parameters'].append(param)
                                #print(final_output)
                return final_output
        else:
                '''
                For single parameter
                '''
                print(Fore.GREEN + f"[+] Testing Parameters:{parameters}")
                final_url = replace(parameters,danger_input,url)
                response = sendRequest(final_url,headers=headers)
                if danger_input in response:
                        print(Fore.BLUE + f"[+] Parameter {parameters} not handling dangerous characters properly!")
                        final_output['parameters'].append(parameters)
                        return final_output

def detect_characters(url,parameter_name=None,headers=None):
        print(Fore. GREEN + f"[+] {url} scan initiated")
        #count = 0
        #final_output = {"url":url,"parameters":[]}
        danger_input =  "><randomstring"
        return testParam(danger_input=danger_input,url=url,headers=headers,parameters=parameter_name)

def validateResponse(val,url,params,dataType,headers=None,verbose=None,returnUrl=False): #make sure to change the verbose option
        #param_names = [] #Determine
        new_val = f"randomstring{val}"
        for param in params:
                final_url =replace(param,new_val,url)
                response = sendRequest(final_url,headers=headers)
                if new_val in response or new_val in response.upper() or new_val in response.lower():
                        printV(Fore.BLUE + f"{dataType} is reflecting {val} in the parameter: {param} ",verbose=verbose)
                        if  "<" in val and ">" in val:
                                val = val.strip(">").strip("<")
                        if returnUrl:
                                return {'url':final_url,'data':val}
                        return val

def check_csp_vulnerabilities(csp_header):
    vulnerabilities = []

    # Convert CSP header to lowercase and split by semicolons
    csp_directives = csp_header.lower().split(';')

    # Check for overly permissive settings
    for directive in csp_directives:
        directive = directive.strip()
        if directive.startswith('script-src') and '*' in directive:
            vulnerabilities.append("Vulnerable: 'script-src *' allows scripts from any source.")
        if directive.startswith('style-src') and '*' in directive:
            vulnerabilities.append("Vulnerable: 'style-src *' allows styles from any source.")
        if directive.startswith('img-src') and '*' in directive:
            vulnerabilities.append("Vulnerable: 'img-src *' allows images from any source.")
        if directive.startswith('font-src') and '*' in directive:
            vulnerabilities.append("Vulnerable: 'font-src *' allows fonts from any source.")

    # Check if 'unsafe-inline' is missing when inline scripts/styles are present
    if any(directive.startswith('script-src') and 'unsafe-inline' not in directive for directive in csp_directives):
        vulnerabilities.append("Warning: Inline scripts may be blocked, but 'unsafe-inline' is not allowed.")
    if any(directive.startswith('style-src') and 'unsafe-inline' not in directive for directive in csp_directives):
        vulnerabilities.append("Warning: Inline styles may be blocked, but 'unsafe-inline' is not allowed.")
    
    return vulnerabilities
                
def fetchPayload(event):
    out = []
    #final_payloads = []
    if event:
        #print(event)
        #quit()
        tag = event.split(' ')[0].strip()
        attribute = event.split(' ')[1].strip()
        #print(f"<{tag} {attribute}>")
        payloads = readFile("src/payloads.txt")
        for payload in payloads:
               #print(payload[:2])
               #break
               if f"<{tag}" == payload[:len(tag)+1]:
                      #print(1)
                      if attribute in payload:
                             out.append(payload)
    return out
        #matcher = rf'<{tag}\b[^>]*\b{attribute}\b[^>]*>.*?</{tag}>'

        #payload_file = readFile("payloads.txt",read=True)
        #out = re.findall(matcher,payload_file)
        #print(out)
        #quit()
        #if out:
        #    #out = [match[0] or match[1] for match in out]
        #    return out

def generate(detect_char_data,threads=None,headers=None,verbose=None,limit=None,tag=None): #Please change this to None
        # Filter out the tags
        if tag:
               tags = [tag]
        else:
               tags = readFile("src/tags.txt")
               #tags += readFile("interaction.txt")
        if limit and tag == None:
               tags = tags[:limit+1]
               #print(1)
        myfunc_tags = partial(validateResponse,headers=headers,url=detect_char_data['url'],params=detect_char_data['parameters'],verbose=verbose,dataType="Parameter")
        with ThreadPoolExecutor(max_workers=threads) as executor:
                final_tags = list(executor.map(myfunc_tags, [f"<{x.strip(chr(10))}>" for x in tags]))
        
        final_tags = [x for x in final_tags if x]
        #quit()
        
        print(Fore.GREEN + "[+] Filtering out the events now!")
        time.sleep(1)
        events = readFile("src/events.txt")
        if limit:
               events = events[:limit+1]
        #New Code
        new_data = []
        for tag in final_tags:
                for event in events:
                        new_data.append(f"<{tag} {event.strip(chr(10))}>")

        myfunc_events = partial(validateResponse,headers=headers,url=detect_char_data['url'],params=detect_char_data['parameters'],verbose=verbose,dataType="Event")
        with ThreadPoolExecutor(max_workers=threads) as executor:
                final_events = list(executor.map(myfunc_events, new_data))
        
        print(Fore.GREEN + "[+] Filtering out the payloads now!")
        time.sleep(1)

        with ThreadPoolExecutor(max_workers=threads) as executor:
                final_payloads = list(executor.map(fetchPayload, final_events))
            
        final_payloads = [item for sublist in final_payloads if sublist is not None for item in sublist if item is not None]
        #print(final_payloads)
        return final_payloads

            

    

def verifyPayload(detect_char_data,threads=None,headers=None,verbose=None,limit=None,tag=None):
        data = generate(detect_char_data,threads,headers,verbose,limit=limit,tag=tag) #Fetch appropriate payloads
        print(Fore.GREEN + f"[+] Loaded {len(data)} Payloads\n[+] Testing The Payloads")
        myfunc_payloads = partial(validateResponse,headers=headers,url=detect_char_data['url'],params=detect_char_data['parameters'],verbose=verbose,dataType="Payload",returnUrl=True)
        with ThreadPoolExecutor(max_workers=threads) as executor:
                result = list(executor.map(myfunc_payloads, data))
        return result

        



def staticTesting(payload,url,data,headers=None,validate=None):
        out = data
        payload = payload.strip(chr(10))
        #print(payload)
        if out:
                for param in out["parameters"]:
                        final_url = replace(param,payload,url)
                        #print(final_url)
                        response = sendRequest(final_url,headers=headers)
                        #with open('a.html','w') as html:
                        #       html.write(response)
                        if payload in response or payload in response.lower() or payload in response.upper():
                                #print(1)
                                if validate:
                                        from validate import validate_js_alert
                                        try:
                                            if validate_js_alert(final_url)['success']:
                                                    print(Fore.RED + f"[+] XSS Validated on {final_url}")
                                                    return final_url
                                        except TypeError:
                                                continue
                                else:
                                        print(Fore.RED + f"[+] Got Something! {final_url}")
                                        return final_url
                        else:
                               print("Not reflecting")
        #quit_browser()
        return None



def generatePayload(url,headers=None,parameter=None,validate=None,verbose=None,save_output=None,threads=None,limit=None,tag=None):
        output = detect_characters(url,parameter,headers=headers)
        #print(output)
        #print(output['url'])
        #tags = []
        #count = 0
        if output:
            final_payloads = verifyPayload(detect_char_data=output,headers=headers,verbose=verbose,threads=threads,limit=limit,tag=tag)
            if final_payloads:
                    if validate:
                            result = []
                            from validate import validate_js_alert
                            for i in final_payloads:
                                   if i:
                                          if validate_js_alert(i['url'])['success']:
                                                print(Fore.RED + f"[+] XSS Validated at {i['url']}")
                                                result.append(i['url'])
                                                break
                                          else:
                                                 printV(f"[+] No Alert at {i['url']}",verbose=verbose)
                            #[print(x['url']) for x in final_payloads if x != None]
                            #with ThreadPoolExecutor(max_workers=threads) as executor:
                            #        result = list(executor.map(validate_js_alert, [x['url'] for x in final_payloads if x != None]))
                            #print(3)
                            #print(result)
                    else:
                        result = [x['url'] for x in final_payloads if x != None]
            else:
                    print(Fore.GREEN + "[-] No Valid Payloads Found")
                    quit()
            for i in result:
                if type(i) == type(True):
                       pass
                else:
                        print(Fore.RED + f"[+] Got Something! {i}")
                if output:
                    saveOutput(i,filename=save_output,verbose=verbose)
            if not result:
                   print(Fore.GREEN + "[-] No Payloads Found! Try --verbose to see the fuzzing in depth")
        else:
                print(Fore.GREEN + "[-] No Valid Payloads Found")

                    
def initialTest(url,headers=None):
        response = sendRequest(url,headers,raw=True)
        
        try:
                out = check_csp_vulnerabilities(response.headers['Content-Security-Policy'])
        except KeyError:
               print(Fore.GREEN + "[+] CSP Headers seems to be not present")
               return
        else:
                for i in out:
                        print(Fore.RED + F"[+] {i}")
        

                       
                        
                

printBanner()

parser = OptionParser()
#parser.add_option('-r',dest='req',help='Enter request body',default=False)
#parser.add_option('-d',dest='domain',help='Crawl domain & scan',default=False)
parser.add_option('-u',dest='url',help='Enter url to scan',default=None)
#parser.add_option('-f',dest='filename',help='Enter a txt file to scan',default=None)
parser.add_option('-p',dest="payloads",help="Enter custom payload file")
parser.add_option('--param',dest="parameter",help="Enter custom payload file")
parser.add_option('--verbose',dest="verbose",help="For Detailed Output",action="store_true")
parser.add_option('-H',dest='headers',help='Add custom headers',default=None)
parser.add_option('-V',dest="validate",help="Validate XSS",default=None,action="store_true")
parser.add_option('-o',dest="output",help="Enter filename to save output",default=None)
parser.add_option('-t',dest="threads",help="Number Of Concurrent Requsts(Default: 5)",default=5)
parser.add_option('--tag',dest="tag",help="Enter custom tag to test",default=None)
parser.add_option('--limit',dest="limit",help="Limit the scan with the given number(Example: If limit is set to 4 then only first 4 tags and events will be used)",default=None)
val,args = parser.parse_args()

val.threads = int(val.threads)
if val.headers:
       def convert_to_dict(header_string):
            # Use regular expression to find key-value pairs
            pairs = re.findall(r'([^,:\s]+):\s*([^,]+)', header_string)
            # Convert list of tuples into a dictionary
            header_dict = {key.strip(): value.strip() for key, value in pairs}
            return header_dict
       val.headers= convert_to_dict(val.headers)


if __name__ == "__main__":
    #print(val.headers)
    print(Fore.GREEN + f"[+] Checking CSP")
    initialTest(val.url,val.headers)
    try:
        if val.payloads:
                print(Fore.GREEN + "[+] Going with static testing!")
                with open(val.payloads,'r') as file:
                        static_payloads = file.readlines()
                        #print(static_payloads)
                detectChars = detect_characters(val.url,val.parameter,val.headers)
                myfunc_static = partial(staticTesting,headers=val.headers,validate=val.validate,url=val.url,data=detectChars)
                with ThreadPoolExecutor(max_workers=val.threads) as executor:
                        result = list(executor.map(myfunc_static,static_payloads))
                result = [x for x in result if x is not None]
                for i in result:
                        saveOutput(i,filename=val.output,verbose=val.verbose)
        else:
                if val.limit:
                       generatePayload(url=val.url,headers=val.headers,parameter=val.parameter,verbose=val.verbose,validate=val.validate,save_output=val.output,threads=val.threads,limit=int(val.limit),tag=val.tag)
                else:
                       generatePayload(url=val.url,headers=val.headers,parameter=val.parameter,verbose=val.verbose,validate=val.validate,save_output=val.output,threads=val.threads,tag=val.tag)
    except KeyboardInterrupt:
            print(Fore.GREEN + f"[-] Keyboard Interrupt Detected! Quitting")
            quit()
    except Exception as e:
           print(Fore.GREEN + f"[-] Error: {e}")

#detect_characters(url="http://testphp.vulnweb.com/hpp/?pp=test")
#getParameters(url="http://testphp.vulnweb.com/hpp/?pp=test&test=batman")

#generatePayload("http://testphp.vulnweb.com/hpp/?pp=test&test=batman")

#if __name__ ==  "__main__":
