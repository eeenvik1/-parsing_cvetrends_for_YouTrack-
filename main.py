import jinja2
import requests
from bs4 import BeautifulSoup
import urllib3
from cpe import CPE
import nvdlib
import ast
import re
import smtplib
from email.message import EmailMessage
config = dotenv_values(".env")


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
YOU_TRACK_TOKEN = config.get("YOU_TRACK_TOKEN")
YOU_TRACK_PROJECT_ID = config.get("YOU_TRACK_PROJECT_ID")
YOU_TRACK_BASE_URL = config.get("YOU_TRACK_BASE_URL")
URL = config.get("YOUR_URL2")

# parse cvetrends.com------------------------------------------------------------------------------------------
def get_top_cve_list():
    link = 'https://cvetrends.com/api/cves/24hrs'
    r = requests.get(link)
    soup = BeautifulSoup(r.text, "lxml")
    regex = re.findall(r'"cve": "CVE-\d{4}-\d{4,8}"', soup.get_text())
    top_cve_list = []
    for item in regex:
        top_cve_list.append(re.search(r'CVE-\d{4}-\d{4,8}', item).group())

    return top_cve_list


# parse microsoft------------------------------------------------------------------------------------------
def check_microsoft(cve):
    msrc_url = f"https://api.msrc.microsoft.com/cvrf/v2.0/Updates('{cve}')"
    get_cvrf_link = requests.get(msrc_url, verify=False)
    return get_cvrf_link.status_code


def get_kb(cve):
    msrc_url = f"https://api.msrc.microsoft.com/cvrf/v2.0/Updates('{cve}')"
    get_cvrf_link = requests.get(msrc_url, verify=False)
    id_for_cvrf = re.search(r'\d{4}-\w{3}', get_cvrf_link.text)
    cvrf_url = f'https://api.msrc.microsoft.com/cvrf/v2.0/document/{id_for_cvrf[0]}'
    get_info = requests.get(cvrf_url, verify=False)
    soup = BeautifulSoup(get_info.text, "html.parser")
    parse_list = []
    buff = ''
    for item in soup.text:
        if item == '\n':
            parse_list.append(buff)
            buff = ''
        else:
            buff += item
    parse_string = ''
    for j, item in enumerate(parse_list):
        regex = re.findall(cve, parse_list[j])
        if regex:
            parse_string = parse_list[j]
    kb_list = re.findall(r'KB\d{7}', parse_string)
    not_remove_list_of_kb = []
    for kb in kb_list:
        if kb not in not_remove_list_of_kb:
            not_remove_list_of_kb.append(kb)
    link_list = []
    for kb in not_remove_list_of_kb:
        kb_url = f'https://catalog.update.microsoft.com/v7/site/Search.aspx?q={kb}'
        test = requests.get(kb_url, verify=False)
        if test.status_code == 200:
            url_get_product = f'https://www.catalog.update.microsoft.com/Search.aspx?q={kb}'
            get_product = requests.get(url_get_product, verify=False)
            soup_get_product = BeautifulSoup(get_product.text, "html.parser")
            product_buff = ''
            for item in soup_get_product.find_all('a', class_='contentTextItemSpacerNoBreakLink'):
                product_buff = item.text
            product = product_buff.strip()
            # link_list.append(f'[{kb}]({kb_url}) - {(product.partition("for")[2])[:-12]}') # Output: Windows 10 Version 1809 for x86-based Systems
            if product:
                link_list.append(f'[{kb}]({kb_url}) - {product}') # Output: 2022-01 Cumulative Update for Windows 10 Version 1809 for x86-based Systems (KB5009557)

    return link_list


# add new tag for new issue------------------------------------------------------------------------------------
def add_tag(id):
    request_payload = {
        "project": {
            "id": YOU_TRACK_PROJECT_ID
        },
        "tags": [
            {
                "name": "В тренде",
                "id": "6-27",
                "$type": "IssueTag"
            }
        ],
    }
    url_differences = f'{YOU_TRACK_BASE_URL}/issues/{id}'
    diff = requests.post(url_differences, headers=headers, json=request_payload)
    return diff.status_code
	
# delete tag for issue-----------------------------------------------------------------------------------------
def delete_tag(id):
    URL1 = f'{YOU_TRACK_BASE_URL}/issues/{id}/tags/6-27'
    delete = requests.delete(URL1, headers=headers)
    return delete.status_code


# change tag for issue-----------------------------------------------------------------------------------------
def change_tag(id):
    request_payload = {
        "project": {
            "id": YOU_TRACK_PROJECT_ID
        },
        "tags": [
            {
                "name": "Была в тренде",
                "id": "6-28",
                "$type": "IssueTag"
            }
        ],
    }
    url_differences = f'{YOU_TRACK_BASE_URL}/issues/{id}'
    diff = requests.post(url_differences, headers=headers, json=request_payload)
    return diff.status_code


# parse github/nu11secur1ty------------------------------------------------------------------------------------
def get_exploit_info(cve):
    link = 'https://github.com/nu11secur1ty/CVE-mitre'
    link_2 = 'https://github.com/nu11secur1ty/CVE-mitre/tree/main/2022'
    default_link = ''
    poc_cve_list = []
    r = requests.get(link)
    soup = BeautifulSoup(r.text, "html.parser")
    for cve_id in soup.find_all("span", class_="css-truncate css-truncate-target d-block width-fit"):
        regex = re.findall(r'CVE-\d{4}-\d{4,8}', cve_id.text)
        if regex:
            poc_cve_list.append(str(regex[0]))

    r = requests.get(link_2)
    soup = BeautifulSoup(r.text, "html.parser")
    for cve_id in soup.find_all("span", class_="css-truncate css-truncate-target d-block width-fit"):
        regex = re.findall(r'CVE-\d{4}-\d{4,8}', cve_id.text)
        if regex:
            poc_cve_list.append(str(regex[0]))

    for item in poc_cve_list:
        if cve == item:
            default_link = f'https://github.com/nu11secur1ty/CVE-mitre/tree/main/{cve}'
    return default_link


# main function for parse cve----------------------------------------------------------------------------------
def get_cve_data(cve):
    template = """
### Описание

{{d.cve}}

### Дата публикации

{{d.lastModifiedDate}}

### Дата выявления

{{d.publishedDate}}


### Продукт, вендор

<details>

{% for vendor in d.product_vendor_list %}{{vendor}}
{% endfor %}


</details>

### CVSSv3 Score

{{d.score}}

### CVSSv3 Vector

{{d.vector}}

### CPE
<details>

{% if d.configurations.nodes %}
{% for conf in d.configurations.nodes %}

#### Configuration {{ loop.index }}
{% if conf.operator == 'AND'%}{% set children = conf.children %}{% else %}{% set children = [conf] %}{% endif %}{% if children|length > 1 %}
**AND:**{% endif %}{% for child in children %}{% if child.cpe_match|length > 1 %}**OR:**{% endif %}{% for cpe in child.cpe_match %}
{{ cpe.cpe23Uri | replace("*", "\*") }}{% endfor %}{% endfor %}{% endfor %}
{% endif %}
</details>

### Links
<details>

{% for link in d.links %}{{ link }}
{% endfor %}


{% if d.exploit_links %}

### Exploit

{% for exploit in d.exploit_links %}{{exploit}}
{% endfor %}
{% endif %}

</details>


{%if d.kb_links %}

### Решение от майкрософт
<details>
<summary>Установить следующие обновления безопасности</summary>

{% for link in d.kb_links %}{{link}}
{% endfor %}
{% endif %}

</details>
    """

    YOU_TRACK_PROJECT_ID = config.get("YOU_TRACK_PROJECT_ID")
    YOU_TRACK_BASE_URL = config.get("YOU_TRACK_BASE_URL")
    URL = config.get("YOUR_URL2")
    pattern = ['Stack-based buffer overflow', 'Arbitrary command execution', 'Obtain sensitive information',
               'Local privilege escalation', 'Security Feature Bypass', 'Out-of-bounds read', 'Out of bounds read',
               'Denial of service', 'Denial-of-service', 'Execute arbitrary code', 'Expose the credentials',
               'Cross-site scripting (XSS)', 'Privilege escalation', 'Reflective XSS Vulnerability',
               'Execution of arbitrary programs', 'Server-side request forgery (SSRF)', 'Stack overflow',
               'Execute arbitrary commands', 'Obtain highly sensitive information', 'Bypass security',
               'Remote Code Execution', 'Memory Corruption', 'Arbitrary code execution', 'CSV Injection',
               'Heap corruption', 'Out of bounds memory access', 'Sandbox escape', 'NULL pointer dereference',
               'Remote Code Execution', 'RCE', 'Authentication Error', 'Use-After-Free', 'Use After Free',
               'Corrupt Memory', 'Execute Untrusted Code', 'Run Arbitrary Code', 'heap out-of-bounds write', 'OS Command injection', 'Elevation of Privilege']
    try:
        r = nvdlib.getCVE(cve, cpe_dict=False)
        cve_cpe_nodes = r.configurations.nodes
        cpe_nodes = ast.literal_eval(str(r.configurations))
        try:
            score = r.v3score
            vector = r.v3vector
        except:
            score = 0.1
            vector = "Нет: cvss vector"
        if vector != "Нет: cvss vector":
            vector = r.v3vector[9:len(r.v3vector)]
        links = []
        exploit_links = []
        links.append(r.url)
        for t in r.cve.references.reference_data:
            links.append(t.url)
            if 'Exploit' in t.tags:
                exploit_links.append(t.url)
        if get_exploit_info(cve):
            exploit_links.append(get_exploit_info(cve))
        cpe_for_product_vendors = []
        if cpe_nodes:
            for conf in cve_cpe_nodes:
                if conf.operator == 'AND':
                    children = [conf.children[0]]
                else:
                    children = [conf]
                for child in children:
                    for cpe in child.cpe_match:
                        cpe_for_product_vendors.append(cpe.cpe23Uri)

    # parse CPE--------------------------------------------------------------------------------------------------------------
        product_vendor_list = []
        product_image_list = []
        version_list = []
        for cpe in cpe_for_product_vendors:
            cpe_parsed = CPE(cpe)
            product = cpe_parsed.get_product()
            vendor = cpe_parsed.get_vendor()
            product_vendor = vendor[0] + " " + product[0] if product != vendor else product[0]
            product_vendor_list.append(product_vendor)
            product_image_list.append(product[0])
            version = cpe_parsed.get_version()
            if (version[0] != '-' and version[0] != '*'):
                version_list.append(f'{product[0]} - {version[0]}')

        temp1 = []
        for item in version_list:
            if item not in temp1:
                temp1.append(item)
        versions = []
        for item in temp1:
            ver = {"name": item}
            versions.append(ver)

        prod = []
        for item in product_image_list:
            if item not in prod:
                prod.append(item)

        content = []
        for item in product_vendor_list:
            con = {"name": item}
            content.append(con)

        value = "Да"
        if not exploit_links:
            value = "Нет"

    # check regex in cve-----------------------------------------------------------------------------------------------------
        cve_name = ''
        cve_info = r.cve.description.description_data[0].value
        for item in pattern:
            if item.upper() in cve_info.upper():
                cve_name = cve + " - " + item
                break
            else:
                cve_name = cve
                
    # check kb in cve------------------------------------------------------------------------------------------------
        kb_links = ''
        if check_microsoft(cve) == 200:
            kb_links = get_kb(cve)
    # message----------------------------------------------------------------------------------------------------------------
        data = {
            'cve': cve_info,
            'lastModifiedDate': r.lastModifiedDate[:-7],
            'publishedDate': r.publishedDate[:-7],
            'configurations': cpe_nodes,
            'score': score,
            'vector': r.v3vector,
            'links': links,
            'product_vendor_list': prod,
            'exploit_links': exploit_links,
            'kb_links': kb_links
        }
        message = jinja2.Template(template).render(d=data)

    # check for product_vendor-----------------------------------------------------------------------------------------------
        URL_get_products = config.get("URL_GET_PRODUCTS")
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
            "Content-Type": "application/json"
        }
        data_prod = requests.get(URL_get_products, headers=headers).json()

        upload_prod = []
        for buff in product_vendor_list:
            upload_prod.append(buff)

        prod_vend = []
        for i in data_prod:
            prod_vend.append(i['name'])

        temp = []
        for iter in upload_prod:
            if iter not in prod_vend:
                temp.append(iter)

        for upload in temp:
            payload = {
                "id": "0",
                "&type": "FieldStyle",
                "name": upload
            }
            requests.post(URL_get_products, headers=headers, json=payload)

    # check for versions----------------------------------------------------------------------------------------------------
        URL_get_vetsions = config.get("URL_GET_VERSIONS")
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
            "Content-Type": "application/json"
        }
        data_ver = requests.get(URL_get_vetsions, headers=headers).json()

        ver_list = []
        for i in data_ver:
            ver_list.append(i['name'])

        temp2 = []
        for iter in temp1:
            if iter not in ver_list:
                temp2.append(iter)

        for upload in temp2:
            payload = {
                "id": "0",
                "&type": "FieldStyle",
                "name": upload
            }
            requests.post(URL_get_vetsions, headers=headers, json=payload)

    # upload information on cve---------------------------------------------------------------------------------------------
        buff_content = []
        buff_versions = []
        if product_vendor_list:
            if re.search(r'windows', str(product_vendor_list[0])):
                con = {"name": "Microsoft Windows"}
                buff_content.append(con)
                buff_versions = versions
            elif re.search(r'juniper', str(product_vendor_list[0])):
                con = {"name": "Juniper"}
                buff_content.append(con)
                buff_versions = versions
            elif re.search(r'adaptive_security_appliance', str(product_vendor_list[0])):
                con = {"name": "Cisco ASA"}
                buff_content.append(con)
                buff_versions = versions
            else:
                if content:
                    buff_content.append(content[0])
                if versions:
                    buff_versions.append(versions[0])

        priority = ''
        if isinstance(score, float):
            if 0.1 <= score <= 3.9:
                priority = 'Низкая'
            elif 4.0 <= score <= 6.9:
                priority = 'Средняя'
            elif 7.0 <= score <= 8.9:
                priority = 'Высокая'
            elif 9.0 <= score <= 10.0:
                priority = 'Критическая'

        request_payload = {
            "project": {
                "id": YOU_TRACK_PROJECT_ID
            },
            "summary": cve_name,
            "description": message,
            "tags": [
                {
                    "name": "В тренде",
                    "id": "6-27",
                    "$type": "IssueTag"
                }
            ],
            "customFields": [
                {
                    "name": "Продукт (пакет)",
                    "$type": "MultiEnumIssueCustomField",
                    "value": buff_content
                },
                {
                    "name": "Есть эксплоит",
                    "$type": "SingleEnumIssueCustomField",
                    "value": {"name": value}
                },
                {
                    "name": "Affected versions",
                    "$type": "MultiEnumIssueCustomField",
                    "value": buff_versions
                },
                {
                    "name": "CVSS Score",
                    "$type": "SimpleIssueCustomField",
                    "value": score

                },
                {
                    "name": "CVSS Vector",
                    "$type": "SimpleIssueCustomField",
                    "value": str(vector)

                },
                {
                    "name": "Priority",
                    "$type": "SingleEnumIssueCustomField",
                    "value": {"name": priority}
                },
            ]
        }
        post = requests.post(URL, headers=headers, json=request_payload)  # Выгрузка инфы о cve в YouTrack
        return post.status_code
    except:
        pass

# email alerting----------------------------------------------------------------------------------------------
def email_alert(cve_list):
    EMAIL_HOST = config.get("EMAIL_HOST")
    EMAIL_PORT = config.get("EMAIL_PORT")
    EMAIL_HOST_PASSWORD = config.get("EMAIL_HOST_PASSWORD")
    EMAIL_HOST_USER = config.get("EMAIL_HOST_USER")
    msg = EmailMessage()
    msg['Subject'] = 'cvetrend.com'
    msg['From'] = EMAIL_HOST_USER
    msg['To'] = ", ".join(recipients)
    if cve_list:
        body = f'Добавлена информация о новой уязвимости {cve_list[0]}'
    else:
        body = f'Добавлена информация о новых уязвимостях\n {cve_list}'
    msg.set_content(body)
    msg.set_content(body)
    smtp_server = smtplib.SMTP_SSL(host=EMAIL_HOST, port=EMAIL_PORT)
    smtp_server.login(user=EMAIL_HOST_USER, password=EMAIL_HOST_PASSWORD)
    smtp_server.send_message(msg)
    print('Email sended {}'.format(msg['Subject']))


#------------------------------MAIN-------------------------------------------------------------------------------------
URL = config.get("URL")
headers = {
    "Accept": "application/json",
    "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
    "Content-Type": "application/json"
}

list_summary = requests.get(URL, headers=headers).json()  # Получение задач с YouTrack

# Получение информации по cve с YouTrack
cve_list = [] # CVE id
id_list = []  # ID Задачи
tag_id = []   # ID Тэга
for i in range(len(list_summary)):
    regex = re.search(r'CVE-\d{4}-\d{4,8}', str(list_summary[i]['summary']))
    if regex != None:
        cve_list.append(str(regex.group()))
        id_list.append(list_summary[i]['id'])
        a = dict(list_summary[i])
        try:
            tag_id.append(a.get('tags')[0].get('id'))
        except:
            tag_id.append('NO')

top_cve_list = get_top_cve_list() # Получение топа cve с cvetrends.com

# Добавление тега к задачам
print(f'Добавление тега:')
repetiotion_cve = []
for i in range(len(cve_list)):
    for j in range(len(top_cve_list)):
        if cve_list[i] == top_cve_list[j]:
            add_tag(id_list[i])
            repetiotion_cve.append(top_cve_list[j])

# Удаление тега с задач, для которых он не актуален и добавление другого тега
remove_list = []
delete_list = []
del_list = []
print(f'Удаление и изменение тега:')
for i in range(len(cve_list)):
    if tag_id[i] == '6-27':  # id искомого тэга (В тренде)
        remove_list.append(cve_list[i])
for item in remove_list:
    if item not in top_cve_list:
        delete_list.append(item)
for i in range(len(cve_list)):
    for j in range(len(delete_list)):
        if cve_list[i] == delete_list[j]:
            del_list.append(id_list[i])
if del_list:
    for i in range(len(del_list)):
        print(f'{i+1} / {len(del_list)} - Удаление: {delete_tag(del_list[i])} - Изменение: {change_tag(del_list[i])}')
else:
    print('None')

# Формирование списка уязвимостей (CVE), которых нет в YouTrack
add_new_cve = []
for item in top_cve_list:
    if item not in repetiotion_cve:
        add_new_cve.append(item)

email_list = []
# Добавление информации о новых уязвимостях в YouTrack
print(f'Добавление информации о новых уязвиомстях:')
if add_new_cve:
    for i in range(len(add_new_cve)):
        print(f'{i+1} / {len(add_new_cve)} - {get_cve_data(add_new_cve[i])}')
        if (get_cve_data(add_new_cve[i])) == 200:
            email_list.append(add_new_cve[i])
else:
    print('None')

# Увемодление на почту
if email_list:
    email_alert(email_list)
