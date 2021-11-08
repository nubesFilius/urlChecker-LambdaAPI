import json
import uuid
import boto3
import re

BASE_ROUTE= '/urlChecker'
GREEDY_ROUTE = '/urlChecker/{proxy+}'

regex = ("(www.)?" +
         "[a-zA-Z0-9@:%._\\+~#?&//=]" +
         "{2,256}\\.[a-z]" +
         "{2,6}\\b([-a-zA-Z0-9@:%" +
         "._\\+~#?&//=]*)")

regex_pattern = re.compile(regex)

def lambda_handler(event, context):
    
    dynamodb = boto3.resource('dynamodb')
    dynamoDB_table = dynamodb.Table('nubesscientia')
    dynamoDB_items =  dynamoDB_table.scan(TableName='Malware_List')['Items']
    
    print(event)
    
    # Grabbing just the route path from request route key.
    route = event['routeKey'].split()[1]
    print(route)
    
    if route == BASE_ROUTE:
        return f'No domain to verify. Please provide a valid domain.'
        
    elif route == GREEDY_ROUTE:
        list_of_domains = event['pathParameters']['proxy'].split('/')
    print(list_of_domains)
    
     
    for full_domain_port in list_of_domains:
        print(full_domain_port)

        # Separating domains from ports, if it has ports
        if ':' in full_domain_port:
            full_domain = full_domain_port.split(':')[0]
        else:
            full_domain = full_domain_port
        print(full_domain)

        if not re.search(regex_pattern, full_domain):
            return f"One of the proxies requested is  ('{full_domain}') is not valid."

        # Splitting full_domain into subdomains
        splitted_full_domain = full_domain.split('.')
        print(splitted_full_domain)

        # Grabbing root_domain from full_domain
        if len(splitted_full_domain) >= 3:
            root_domain = splitted_full_domain[-2] + \
                '.' + splitted_full_domain[-1]
        elif len(splitted_full_domain) == 2:
            root_domain = full_domain
        else:
            return f"Root domain '{full_domain}' is not valid."
        print(root_domain)

        for malware in dynamoDB_items:
            if root_domain in malware["root-domain"]:
                print(f'"malware["root-domain"]" has malware')
                return f'Malware detected for "{root_domain}".'
    return f'No malware.'
