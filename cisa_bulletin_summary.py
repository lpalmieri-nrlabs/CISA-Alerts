import requests
from bs4 import BeautifulSoup
import polars as pl
import re
import summarize_ai as ai
from asksageclient import AskSageClient
import time

#Functions-----------------------------------------------------------------------------------------------------
def fetch_advisory_links(url):
    """
    Fetches advisory titles and their URLs from the given CISA advisories page URL,
    specifically within 'article' elements with the class 'is-promoted c-teaser c-teaser--horizontal'.

    Parameters:
        url (str): The URL of the CISA Cybersecurity Advisories page.

    Returns:
        list of dict: A list containing dictionaries with 'title' and 'url' keys for each advisory.
    """
    advisory_list = []
    
    try:
        # Send a GET request to fetch the page content
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse the HTML content
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find All 'article' elements with the specified class
        advisory_articles = soup.find_all('article', class_='is-promoted c-teaser c-teaser--horizontal')


        #get dates
        time_elements = soup.find_all("time")
        dates = [date.get_text() for date in time_elements]
        
        
        
        print(len(advisory_articles))
        # Find the link within the article
        for article in advisory_articles:
            # Find the <a> tag with an href attribute

            link = article.find('a')
            
            if link:
                
                advisory_title = link.get_text(strip=True)
                advisory_url = link['href']
                
                # Ensure the URL is absolute
                if not advisory_url.startswith('http'):
                    advisory_url = 'https://www.cisa.gov' + advisory_url
                advisory_list.append({'title': advisory_title, 'url': advisory_url})
            


    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching the URL: {e}")


    return list(zip(dates, advisory_list))


def fetch_advisory_text(url):
    """
    Fetches advisory text
    
    Parameters:
        url (str): The URL of the CISA Cybersecurity Advisories page.

    Returns:
        text from advisory
    """
    iocs = 'No IOCs'
    try:
        # Send a GET request to fetch the page content
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse the HTML content
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all divs with class 'c-file__download'
        download_divs = soup.find_all('div', class_='c-file__download')

        # Get all text from the webpage
        all_text = soup.get_text(separator=' ', strip=True)
        
        for div in download_divs:
            # Find all <a> tags within the div
            links = div.find_all('a')
            for link in links:
                if not link:
                    iocs = 'No IOCs'
                    
                if 'JSON' in link.get_text(strip=True): 
                    print(link.get_text(strip=True))
                    file_url = link['href']
                    iocs = requests.get('https://cisa.gov' + file_url)
                
        
        

    
        
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching the URL: {e}")
        
    return iocs, all_text


def parse_stix(pattern):
    emails = [m for m in re.findall(r"'(.*?)'", pattern) if "email-addr:value" in pattern]
    
    hashes = [m for m in re.findall(r"'(.*?)'", pattern) if "file:hashes." in pattern]
    hashes = [m for m in hashes if "SHA" not in m]
    hashes = [m for m in hashes if len(m) == 32] #Filter so only MD5
    
    print('checking ips')
    ipv4 = [m for m in re.findall(r"'(.*?)'", pattern) if "ipv4-addr:value" in pattern]
    #ipv4 = [m + ' ' + ip_score(m) for m in ipv4] #risk scoring
    ipv4 = [m.replace('.', '[.]') for m in ipv4]
    ipv4 = [m for m in ipv4 if m not in check_ips()]
 
    
    ipv6 = [m for m in re.findall(r"'(.*?)'", pattern) if "ipv6-addr:value" in pattern]
    ipv6 = [m.replace('.','[.]') for m in ipv6]
    
    domains = [m for m in re.findall(r"'(.*?)'", pattern) if "domain-name:value" in pattern]
    domains = [m.replace('.','[.]') for m in domains]
    domain_count = len(domains)
    domains = [m for m in domains if m not in check_domains()]

    output = {'Emails': emails,'Hashes':hashes, 'IPv4':ipv4,  'IPv6':ipv6, 'Domains':domains}
    
    return(output)


def extract_iocs(stix_list):
    iocs = {'Emails': [],'Hashes':[], 'IPv4':[], 'IPv6':[], 'Domains':[]}
    
    for pattern in stix_list:
        parsed = parse_stix(pattern)
        for key, values in parsed.items():
            iocs[key].extend(values)

    
    # Remove any keys where the value list is empty
    output = {k: v for k, v in iocs.items() if v}

    return(output)


def dict_to_text(ioc_dict):
    lines = []
    ask_sage_response=''
    for key, values in ioc_dict.items():
        lines.append(f"{key}:")
        lines.extend(values)
        lines.append("")  # Blank line between sections
    return "\n".join(lines)


def check_ips():
    df = pl.read_csv('defanged_indicators.csv')
    df = df.filter(pl.col('type') == 'IPv4')
    ip_list = df['indicator'].unique().to_list()
    return ip_list


def check_domains():
    df = pl.read_csv('defanged_indicators.csv')
    df = df.filter(pl.col('type') == 'Domain')
    domain_list = df['indicator'].unique().to_list()
    return domain_list



def ip_score(ip):
    response = requests.get(f"https://ip-intelligence.abstractapi.com/v1/?api_key=b7410b99b7b44c31808fc10bbe7d83bf&ip_address={ip}")
    if response.status_code == 200:
        res = response.json()
        score = res.get('security',{}).get('is_abuse', '0')
        asn = res.get('asn', {}).get('name','')
        if asn is None:
            asn=''
        if score is None:
            score=''
        if score is True or score is False:
            score = str(int(score)) # turn into 1 or 0 
            
        time.sleep(2)
        
        text =  ' Risk Score: ' + score + ' ASN: ' + asn
        
        return text 
    else:
        return ''
#Main loop and AI------------------------------------------------------------------------------------------------------

def generate_report():

    #store reports 
    reports =[]
    # Load the credential
    credentials = ai.load_credentials('creds.json')
    
    # Extract the API key, and email from the credentials to be used in the API request
    api_key = credentials['credentials']['api_key']
    email = credentials['credentials']['Ask_sage_user_info']['username']
    
    
    ask_sage_client = AskSageClient(email, api_key)

    bulletins = fetch_advisory_links("https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94")

    for bulletin in bulletins[7:8]:
        
        ioc_data = fetch_advisory_text(bulletin[1]['url'])
        title = bulletin[1]['title']
        text = ioc_data[1]

        summary = ai.summarize(text, ask_sage_client)
        
        if ioc_data[0] != 'No IOCs':
            cisa_json =  [j for j in  ioc_data[0].json()['objects'] if j['type'] == 'indicator']
            cisa_iocs = [item['pattern'] for item in cisa_json]
            iocs = extract_iocs(cisa_iocs)
            
            pretty_iocs = dict_to_text(extract_iocs(cisa_iocs))
            
            
        else:
            pretty_iocs = 'No IOCs'
            
            

        report = f'''
--------------------------------------------------------------------------------------------
CISA Bulletin: {title}
--------------------------------------------------------------------------------------------
Summary:
{summary}


________________________
IOCs To Be Blocked:
{pretty_iocs}
________________________
'''
        reports.append(report)
    return reports


if __name__ == "__main__":
    main()


        


