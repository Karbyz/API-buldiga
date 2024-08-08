import requests
from datetime import datetime
import json
import ipaddress
import re
from flask import Flask, request, render_template, redirect, url_for
from flask import Response, stream_with_context
from ipaddress import ip_address, ip_network, IPv4Address
import os
import time


CURRENT_ROW_FILE = 'row.txt'
app = Flask(__name__)
access_token = 'token'
file_id = 'file id'
sheet_name = 'BLOCKED IP'

origin_choices = [
    'Qradar', 'KATAP', 'Kaspersky-Alert', 'ptaf', 'Microsoft-Defender', 
    'Sec-IS', 'IoC', 'ForcePoint', 'Anti-DDoS', 'SnapShot'
]

blocked_ips = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
}

def update_column_d_in_excel(access_token, file_id, sheet_name , first_empty_row):
    data = {
        "values": [
            [
                'exists',  
            ]
        ]
    }
    range_address = f"D{first_empty_row}:D{first_empty_row}"
    url = f'https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/workbook/worksheets/{sheet_name}/range(address=\'{range_address}\')'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
    }
    response = requests.patch(url, headers=headers, json=data)
    response.raise_for_status()  
    return response.json()

def login(user,password):
    payload = {'user':user, 'password' : password}
    response = api_call('Console ip', 443, 'login',payload, '') 
    if 'sid' in response:        
        return response['sid']    
    else:         
        raise Exception( 'Login failed: ' + json.dumps(response))

def get_current_row_from_file():
    if os.path.exists(CURRENT_ROW_FILE):
        with open(CURRENT_ROW_FILE, 'r') as file:
            try:
                current_row = int(file.read().strip())
            except ValueError:
                current_row = 1
    else:
        current_row = 1
    return current_row

def save_current_row(row):
    with open(CURRENT_ROW_FILE, 'w') as file:
        file.write(str(row))

def is_ip_blocked(ip):
    try:
        ip_obj = ip_address(ip)
        print(ip_obj)
        if not isinstance(ip_obj, IPv4Address):
            return True
    except ValueError:
        return True

    for blocked_ip in blocked_ips:
        try:
            if ip_obj in ip_network(blocked_ip, strict=False):
                return True
        except ValueError:
            continue

    return False

def remove_cidr_suffix(ip_with_cidr):
    ip_address = ip_with_cidr.split('/')[0]
    return ip_address

def get_netmask(ip_with_cidr):
    network = ipaddress.IPv4Network(ip_with_cidr, strict=False)
    return network.netmask

def set_cell_fill_color(access_token, file_id, sheet_name, cell_address, hex_color):
    url = f'https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/workbook/worksheets/{sheet_name}/range(address=\'{cell_address}\')/format/fill'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
    }
    data = {
        "color": hex_color
    }
    response = requests.patch(url, headers=headers, data=json.dumps(data))
    response.raise_for_status() 
    return response.json()

def get_first_empty_row(access_token, file_id, sheet_name):
    url = f'https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/workbook/worksheets/{sheet_name}/usedRange'
    headers = {
        'Authorization': f'Bearer {access_token}',
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()

    if 'values' in data:
        rows = data['values']
        for i, row in enumerate(rows):
            if len(row) > 1 and not row[1]:  
                return i + 1  
        return len(rows) + 1  
    return 1 

def add_row_to_excel(access_token, file_id, sheet_name, row_data):
    first_empty_row = get_first_empty_row(access_token, file_id, sheet_name)
    
    data = {
        "values": [
            [
                row_data.get('A', ''),  
                row_data.get('B', ''),  
                row_data.get('C', ''),  
                '',  
                '',  
                '',  
                '',  
                row_data.get('H', ''),  
            ]
        ]
    }

    range_address = f'A{first_empty_row}:H{first_empty_row}'
    url = f'https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/workbook/worksheets/{sheet_name}/range(address=\'{range_address}\')'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
    }
    response = requests.patch(url, headers=headers, json=data)
    cell_address = f'D{first_empty_row}'
    set_cell_fill_color(access_token, file_id, sheet_name, cell_address, '#FFFF00')
    response.raise_for_status()  
    return response.json()

def add_data_to_excel(ip, origin):
    now = datetime.now()
    ninche = now.strftime('%d.%m.%Y') 
    if is_ip_blocked(ip):
        return "недопустимый ip"
    else:
        if "/" in ip:
            aboba = get_netmask(ip)
            ip_bez_maski = ip.split('/')[0]
            atas = f"add network name Network_{ip} subnet {ip_bez_maski} subnet-mask {aboba} groups Block_Host_Group"
        else:
            atas = f"add host name Host_{ip} ip-address {ip} groups Block_Host_Group"

        row_data = {
            'A': ninche,
            'B': ip,
            'C': origin,
            'H': atas
        }
        add_row_to_excel(access_token, file_id, sheet_name, row_data)
        return "Данные успешно добавлены."

def get_fill_color(access_token, file_id, sheet_name, row):
    url = f'https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/workbook/worksheets/{sheet_name}/range(address=\'D{row}\')/format/fill'
    headers = {
        'Authorization': f'Bearer {access_token}',
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def get_cell_value(access_token, file_id, sheet_name, row, column):
    url = f'https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/workbook/worksheets/{sheet_name}/range(address=\'{column}{row}\')'
    headers = {
        'Authorization': f'Bearer {access_token}',
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()
    return data.get('values', [[None]])[0][0]  

def analyze_excel_file(access_token, file_id, sheet_name, process_function, sid):
    current_row = get_current_row_from_file()

    while True:
        fill_color_response = get_fill_color(access_token, file_id, sheet_name, current_row)
        fill_color = fill_color_response.get('color', '')
        
        
        row2 = f"D{current_row}"
        if fill_color == '#FFFF00':
            cell_value = get_cell_value(access_token, file_id, sheet_name, current_row, 'H')
            set_cell_fill_color(access_token, file_id, sheet_name, row2, '#4EA72E')
            if cell_value:
                result = process_function(cell_value, sid)  
                print(f'Processed result: {result}')
                yield f"<p>Row {current_row}: {cell_value} - {result}</p>"
        else:
                yield f"<p>зелененькая</p>"
        if fill_color == '#FFFFFF':
            time.sleep(5)
            break
        save_current_row(current_row)
        current_row += 1

def add_host(name, ip_address, group, sid):
    new_host_data = {
        'name': name,
        'ip-address': ip_address,
        'groups': group
    }
    result = api_call('Console ip', 443, 'add-host', new_host_data, sid)
    print("Add host response: " + json.dumps(result))  
    return result
 
def add_network(name, subnet, subnet_mask, group, sid):
    new_network_data = {
        'name': name,
        'subnet': subnet,
        'subnet-mask': subnet_mask,
        'groups': group
    }
    result = api_call('Console ip', 443, 'add-network', new_network_data, sid)
    print("Add network response: " + json.dumps(result))  
    return result
    
def parse_input(input_str, sid):
    current_row = get_current_row_from_file()
    input_str = input_str.strip()
    if input_str.startswith("add network"):
        match = re.match(r'add network name ([^\s]+) subnet ([^\s]+) subnet-mask ([^\s]+) groups ([^\s]+)', input_str)
        if match:
            name, subnet, subnet_mask, group = match.groups()
            json_add_network = add_network(name, subnet, subnet_mask, group, sid)
            if json_add_network[ 'code' ] == 'err_validation_failed' and any ( 'exists' in error[ 'message' ] for error in json_add_network[ 'errors' ]):
                print("123")
                update_column_d_in_excel(access_token, file_id, sheet_name, current_row)
            return json_add_network
    elif input_str.startswith("add host"):
        match = re.match(r'add host name (\S+) ip-address (\S+) groups (\S+)', input_str)
        if match:
            name, ip_address, group = match.groups()
            json_add_host = add_host(name, ip_address, group, sid)
            if json_add_host[ 'code' ] == 'err_validation_failed' and any ( 'exists' in error[ 'message' ] for error in json_add_host[ 'errors' ]):
                print("123")
                update_column_d_in_excel(access_token, file_id, sheet_name, current_row)
            return json_add_host
    else:
        print("Unknown command")
        return "Unknown command"

def generate_results():
    results = "<html><body><ul>"
    for result in analyze_excel_file(access_token, file_id, sheet_name, max_row=10, process_function=parse_input, sid=sid):
        results += f"<li>{result}</li>"
    results += "</ul></body></html>"
    return results

def api_call(ip_addr, port, command, json_payload, sid):
    url = f"https://{ip_addr}:{port}/web_api/{command}"
    if sid == '':
        request_headers = {'Content-Type' : 'application/json'}
    else:
        request_headers = {'Content-Type' : 'application/json', 'X-chkp-sid' : sid}
    r = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=False)
    return r.json()

def login(user,password):
    payload = {'user':user, 'password' : password}
    response = api_call('Console ip', 443, 'login',payload, '') 
    if 'sid' in response:        
        return response['sid']    
    else:         
        raise Exception( 'Login failed: ' + json.dumps(response))

def publish_changes(sid):
    response = api_call('Console ip', 443, 'publish', {}, sid)
    print("Publish response: " + json.dumps(response))  
    return response

sid = login('secret','secret')
print("session id: " + sid)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        value = int(request.form['value'])
        if value == 1:
            return redirect(url_for('input_ip'))
        elif value == 2:
            return redirect(url_for('parse'))
    return render_template('index.html')

@app.route('/input_ip', methods=['GET', 'POST'])
def input_ip():
    result = None
    if request.method == 'POST':
        ip = request.form['ip_address']
        origin_choice = int(request.form['origin_choice'])
        origin = origin_choices[origin_choice - 1]
        result = add_data_to_excel(ip, origin)
    return render_template('input_ip.html', result=result, origin_choices=origin_choices)

@app.route('/parse_input', methods=['GET', 'POST'])
def parse():
    if request.method == 'POST':
        if 'publish_changes' in request.form:
            publish_changes(sid)
            time.sleep(40)
            return 'Changes published successfully', 200
        else:
            return Response(stream_with_context(analyze_excel_file(access_token, file_id, sheet_name, process_function=parse_input, sid=sid)), content_type='text/html')
    return render_template('parse_input.html', sid=sid)

if __name__ == '__main__':
    app.run(debug=True)
