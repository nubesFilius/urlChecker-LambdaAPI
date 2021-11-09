import json
import uuid
import boto3
import re

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
        
    list_of_domains = event['pathParameters']['proxy'].split('/')
    print(list_of_domains)
     
    for full_domain_port in list_of_domains:

        # Separating domains from ports, if it has ports
        if ':' in full_domain_port:
            full_domain = full_domain_port.split(':')[0]
        else:
            full_domain = full_domain_port

        if not re.search(regex_pattern, full_domain):
            message = f'One of the proxies requested "{full_domain}" is not valid.'
            return {'body': json.dumps(message) }

        # Splitting full_domain into subdomains
        splitted_full_domain = full_domain.split('.')

        # Grabbing root_domain from full_domain
        if len(splitted_full_domain) >= 3:
            root_domain = splitted_full_domain[-2] + \
                '.' + splitted_full_domain[-1]
        elif len(splitted_full_domain) == 2:
            root_domain = full_domain
        else:
            message = f'Root domain "{root_domain}" is not valid.'
            return {'body': json.dumps(message) }

        print(root_domain)

        for malware in dynamoDB_items:
            if root_domain in malware["root-domain"]:
                message = f'Malware detected for "{root_domain}".'
                return {'body': json.dumps(message) }
    message = 'No Malware detected.'
    return {'body': json.dumps(message) }