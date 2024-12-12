import os
import requests
import argparse
import getpass
import sys
import json
from functools import wraps
import csv
from prettytable import PrettyTable
import random
import string

# Global Variable
customer = ''
env = ''
password = ''
token = ''
opt = ''
configurationFile = ''
ssl = ''
user = ''

# Configuration
config = {
    'customer': {
        '': {
            'realmApp': '',
            'realmAdmin': 'master',
            'username': '',
            'baseurl': '',
            'ssl': 'True'
        }
    }
}


# Functions
def show(var):
    if var == "ss":
        print(json.dumps(config, indent=2))
    elif var == "s":
        for customer, env in config.items():
            listEnv = ""
            for env in env.keys():
                listEnv += (f"{env} ")
            print(f"> {customer} {listEnv}")
        print(f"")
    sys.exit()


def gen_password():
    caratteri = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(caratteri) for _ in range(20))
    return password

def getInput():
    parser = argparse.ArgumentParser(description="# Keycloak REST API - ADMIN")

    parser.add_argument('-c', '--customer', type=str)
    parser.add_argument('-e', '--env', type=str)
    parser.add_argument('-o', '--opt', type=str,
                        choices=['downloadGroupAndRole', 'UploadGroupAndRole', 'UploadUsers', 'EnableUsers',
                                 'disableUsers', 'createSystemUser', 'exportUsers', 'UploadGroupAttributes'])
    parser.add_argument('-f', '--file', type=str, required=False, default='')
    parser.add_argument('-u', '--user', type=str, required=False, default=None)
    parser.add_argument('-s', '--showConfig', action="store_true")
    parser.add_argument('-ss', '--showConfigJson', action="store_true")

    args = parser.parse_args()

    if args.showConfig:
        show('s')
    if args.showConfigJson:
        show('ss')

    if args.customer and args.env and args.opt:
        password = getpass.getpass(prompt='Password: ')
    else:
        parser.print_help()
        sys.exit()

    if args.opt == 'createSystemUser' and (args.user == None):
        parser.error("--opt createSystemUser , requires --user")

    return args.customer, args.env, password, args.opt, args.file, args.user

def getToken():
    """Genera un nuovo token di accesso."""
    global token
    url = config[customer][env]['baseurl'] + "/realms/" + config[customer][env][
        'realmAdmin'] + "/protocol/openid-connect/token"
    payload = {
        'username': config[customer][env]['username'],
        'password': password,
        'grant_type': 'password',
        'client_id': 'admin-cli'
    }

    print(payload)
    try:
        response = requests.post(url, data=payload, verify=ssl)
        response.raise_for_status()
        print(response)
        token = response.json()['access_token']
        print(f"Token retrieved successfully for {customer} in {env} environment.")
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving token: {e}")
        sys.exit(1)

def handle_token(func):
    """Gestisce il token scaduto e lo rigenera se necessario."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        global token
        try:
            return func(*args, **kwargs)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:  # Token scaduto
                print("Token scaduto, rigenerazione in corso...")
                getToken()  # Rigenera il token
                return func(*args, **kwargs)  # Riprova la funzione originale con il nuovo token
            else:
                raise

    return wrapper

@handle_token
def getGroups():
    try:
        """Scarica i gruppi dal server Keycloak."""
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env]['realmApp'] + "/groups"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, verify=ssl)
        response.raise_for_status()
        groups = response.json()
        return groups
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 401:
            print("ERROR:", response.json()['errorMessage'])
        else:
            raise

@handle_token
def getGroup(group):
    try:
        """Restituisce il group id, se non esiste restituisce"""
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env][
            'realmApp'] + "/groups" + "?search=" + group
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, verify=ssl)
        response.raise_for_status()
        group_result = response.json()
        if not group_result:
           return ''
        else:
            for i in range(len(group_result)):
                if group_result[i]['name'] == group:
                    print(group_result[i]['id'])
                    return group_result[i]['id']
            return ''
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 401:
            print("ERROR:", response.json()['errorMessage'])
        else:
            raise

@handle_token
def getRole(role):
    try:
        """Restituisce il role id, se non esiste restituisce"""
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env][
            'realmApp'] + "/roles" + "?search=" + role
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

        response = requests.get(url, headers=headers, verify=ssl)
        response.raise_for_status()
        role_result = response.json()
        if not role_result:
            return ''
        else:
            for i in range(len(role_result)):
                print(role_result[i]['name'])
                if role_result[i]['name'] == role:
                    print(role_result[i]['id'])
                    return role_result[i]['id']
            return ''
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 401:
            print("ERROR:", response.json()['errorMessage'])
        else:
            raise

@handle_token
def getRolesMapping(group_id):

    try:
        """Scarica i ruoli associati a un gruppo dal server Keycloak."""
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env][
            'realmApp'] + "/groups/" + group_id + "/role-mappings"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, verify=ssl)
        response.raise_for_status()
        roles = response.json()
        sort_roles = []
        if "realmMappings" in roles:
            for role in roles['realmMappings']:
                sort_roles.append(role['name'])
            # print(f"ROLE: {role['name']} ({role['id']})")
        sort_roles.sort()
        return sort_roles
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 401:
            print("ERROR:", response.json()['errorMessage'])
        else:
            raise

@handle_token
def addRole(role):
    try:
        """Crea il ruolo"""
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env]['realmApp'] + "/roles"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        BodyRequest = {"name": role}
        response = requests.post(url, json=BodyRequest, headers=headers, verify=ssl)
        response.raise_for_status()
        print("Role: ", role, "created!")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 401:
            print("ERROR:", response.json()['errorMessage'])
        else:
            raise

@handle_token
def addGroup(group):
    try:
        """Crea il gruppo"""
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env]['realmApp'] + "/groups"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        BodyRequest = {"name": group}
        response = requests.post(url, json=BodyRequest, headers=headers, verify=ssl)
        response.raise_for_status()
        print("Group: ", group, "created!")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 401:
            print("ERROR:", response.json()['errorMessage'])
        else:
            raise

@handle_token
def addMapping(obj_mapping):
    """Effettua l'associazione gruppo ruolo"""
    try:
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env]['realmApp'] + "/groups/" + \
              obj_mapping['id_group'] + "/role-mappings/realm"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        BodyRequest = [{'id': obj_mapping['id_role'], 'name': obj_mapping['name_role']}]
        response = requests.post(url, json=BodyRequest, headers=headers, verify=ssl)
        response.raise_for_status()
        print("Mapping: ", obj_mapping['name_group'], "<--->", obj_mapping['name_role'], " completed!")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 401:
            print("ERROR: Mapping: ", obj_mapping['name_group'], "<--->", obj_mapping['name_role'],
                  response.json()['errorMessage'])
        else:
            raise

@handle_token
def addMappingAttribute(group_name, group_id, new_attributes):
    """Effettua l'associazione gruppo attributo"""
    try:
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env]['realmApp'] + "/groups/" + \
              group_id

        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, verify=ssl)
        ## Mi vado a prendere gli attributi gia presenti
        group_data = response.json()
        existing_attributes = group_data.get("attributes", {})
        print(existing_attributes)
        for key, value in new_attributes.items():
            if key in existing_attributes:
                if isinstance(existing_attributes[key], list):
                    existing_attributes[key].append(value)
                else:
                    existing_attributes[key] = [existing_attributes[key], value]
            else:
                existing_attributes[key] = [value]

        print(existing_attributes)

        data = {
            "name": group_name,
            "attributes": existing_attributes
        }
        response = requests.put(url, json=data, headers=headers, verify=ssl)
        print(response.raise_for_status())
        print("Mapping: ", group_id, "<--->", data, " completed!")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 401:
            print("ERROR: Mapping: ", group_id, "<--->", data,
                  response.json()['errorMessage'])
        else:
            raise

def downloadGroupAndRole():
    groups = getGroups()
    content = []
    for group in groups:
        # print(f"GROUP: {group['name']} ({group['id']})")
        group_name = group['name']
        roles = getRolesMapping(group['id'])
        content.append([group_name + ',' + role for role in roles])
        roles_list = [[r] for r in roles]
        prettyPrint(group_name, roles_list)

    write_csv(content)

def prettyPrint(group, roles):
    table = PrettyTable()
    table.field_names = [group]
    table.add_rows(
        roles
    )
    print(table)
    print()

def write_csv(content):
    csvfile = ""
    match opt:
        case 'downloadGroupAndRole':
            csvfile = f'{customer}-{env}GroupAndRole.csv'

            with open(csvfile, 'w', newline='') as file:
                writer = csv.writer(file, delimiter=';')
                writer.writerow(["Group", "Role"])
                for i in range(len(content)):
                    for j in content[i]:
                        row = j.split(",")
                        writer.writerow([row[0], row[1]])

            print("CSV Created!.." + csvfile)
        case 'exportUsers':
            csvfile = f'{customer}-{env}exportUsers.csv'
            with open(csvfile, 'w', newline='') as file:
                writer = csv.writer(file,delimiter=';')
                writer.writerow(["name","lastName","Email","Attach_idp(BOOL)","idpName(default:EMPTY)","DoMappingGroups(BOOL)","group1,group2,group3","createPassword(BOOL)"])
                for item in content:
                    if len(item["groups"]) == 0:
                        writer.writerow([item["firstName"], item["lastName"], item["email"], "TRUE", "EMPTY", "FALSE",
                                         item["groups"], "FALSE"])
                    elif len(item["groups"]) > 0:
                        writer.writerow([item["firstName"],item["lastName"],item["email"],"TRUE","EMPTY","TRUE",item["groups"],"FALSE"])
                    else:
                        print(item["email"]," skipped!")

@handle_token
def UploadGroupAndRole():
    validateConfigurationFile(2, "Group;Role")
    with open(configurationFile, "r") as file:
        lines = file.readlines()[1:]
        for line in lines:
            if not (len(line.strip()) == 0):
                line_argument = line.split(";")
                group = line_argument[0].rstrip('\n')
                role = line_argument[1].rstrip('\n')
                ### Verifico se non sono presenti in tal caso li vado a creare
                group_id = getGroup(group)
                role_id = getRole(role)

                if group_id == '':
                    print("Group:", group_id, "not present, creating ...")
                    addGroup(group)
                    group_id = getGroup(group)
                if role_id == '':
                    print("Role:", role_id, "not present, creating ...")
                    addRole(role)
                    role_id = getRole(role)
                obj_mapping = {
                    'id_group': group_id,
                    'name_role': role,
                    'id_role': role_id,
                    'name_group': group
                }
                addMapping(obj_mapping)


@handle_token
def UploadUsers():
    """Create user and set temporary password"""
    validateConfigurationFile(8, "name;lastName;Email,Attach_idp(BOOL);idpName(default:EMPTY);DoMappingGroups(BOOL);group1,group2,group3;createPassword(BOOL)")
    with open(configurationFile, "r") as file:
        # lines = file.readlines()
        lines = file.readlines()[1:]
        for line in lines:
            if not (len(line.strip()) == 0):
                line_argument = line.split(";")
                # name;lastName;Email,Attach_idp(BOOL);idpName(default:EMPTY);DoMappingGroups(BOOL);group1,group2,group3;createPassword(BOOL)
                name = line_argument[0].rstrip('\n')
                lastname = line_argument[1].rstrip('\n')
                email = line_argument[2].rstrip('\n')
                idp = line_argument[3].rstrip('\n')
                idpName = line_argument[4].rstrip('\n')
                doMappingGroupIDP = line_argument[5].rstrip('\n')
                groups = line_argument[6].rstrip('\n').replace('"', '').split(',')
                createPwd = line_argument[7].rstrip('\n')

                url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env]['realmApp'] + "/users"
                headers = {
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json'
                }

                if idp == "FALSE":
                    if createPwd == "TRUE":
                        BodyRequest = {
                            'email': email,
                            'emailVerified': 'false',
                            'enabled': 'true',
                            'firstName': name,
                            'lastName': lastname,
                            'username': email,
                            'groups': groups,
                            'attributes': {
                               # 'mandanteId': '10'
                            },
                            'credentials': [{
                                'temporary': 'true',
                                'type': 'password',
                                'value': email
                            }]
                        }
                    else:
                        BodyRequest = {
                            'email': email,
                            'emailVerified': 'false',
                            'enabled': 'true',
                            'firstName': name,
                            'lastName': lastname,
                            'username': email,
                            'groups': groups
                        }
                elif idp == "TRUE":
                    if idpName == "EMPTY":
                        if doMappingGroupIDP == "TRUE":
                            BodyRequest = {
                                'email': email,
                                'emailVerified': 'false',
                                'enabled': 'true',
                                'firstName': name,
                                'lastName': lastname,
                                'username': email,
                                'groups': groups,
                                'attributes': {
                                #'mandanteId': '10226'
                                }
                            }
                        else:
                            BodyRequest = {
                                'email': email,
                                'emailVerified': 'false',
                                'enabled': 'true',
                                'firstName': name,
                                'lastName': lastname,
                                'username': email,
                                'attributes': {
                                    #'mandanteId': '10'
                                },
                            }
                    else:
                        if doMappingGroupIDP == "TRUE":
                            BodyRequest = {
                                'email': email,
                                'emailVerified': 'false',
                                'enabled': 'true',
                                'firstName': name,
                                'lastName': lastname,
                                'username': email,
                                'groups': groups,
                                'attributes': {
                                    #'mandanteId': '10'
                                },
                                'federatedIdentities': [{
                                    'identityProvider': idpName,
                                    'userId': email,
                                    'userName': email
                                }]

                            }
                        else:
                            BodyRequest = {
                                'email': email,
                                'emailVerified': 'false',
                                'enabled': 'true',
                                'firstName': name,
                                'lastName': lastname,
                                'username': email,
                                'federatedIdentities': [{
                                    'identityProvider': idpName,
                                    'userId': email,
                                    'userName': email
                                }]

                            }

                try:
                    response = requests.post(url, json=BodyRequest, headers=headers, verify=ssl)
                    response.raise_for_status()
                    print("User ", email, "created!")
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code != 401:
                        error_message = response.json()['errorMessage']
                        print("ERROR:", email, error_message)
                        if error_message == "User exists with same username":
                            """Rimuovo l'utenza"""
                            removeUser(email)
                            response = requests.post(url, json=BodyRequest, headers=headers, verify=ssl)
                            response.raise_for_status()
                            print("User ", email, "created!")
                    else:
                        raise


@handle_token
def resetPassword(username, password):
    """Set as a temporary password email of user"""
    try:
        ### GET ID OF USER
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env][
            'realmApp'] + "/users" + "?search=" + username
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, verify=ssl)
        user_result = response.json()

        ### RESET PASSWORD
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env]['realmApp'] + "/users/" + \
              user_result[0]['id'] + "/reset-password"

        BodyRequest = {
            'temporary': 'true',
            'type': 'password',
            'value': password
        }
        response = requests.put(url, json=BodyRequest, headers=headers, verify=ssl)
        response.raise_for_status()
    except:
        print("ERROR:", username, response.json()['errorMessage'])

@handle_token
def removeUser(username):
    """Rimuove l'utenza con l'username passato"""
    try:
        ### GET ID OF USER
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env][
            'realmApp'] + "/users" + "?search=" + username
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, verify=ssl)
        user_result = response.json()
        print(user_result)
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env]['realmApp'] + "/users/" + \
              user_result[0]['id']
        print(url)
        response = requests.delete(url, headers=headers, verify=ssl)
        print(response.raise_for_status())
    except:
        print("ERROR:", username, response.json()['errorMessage'])


def enableUsers():
    if not os.path.isfile(configurationFile):
        sys.exit("ERROR: No configurazion file, please specify option -f ")
    with open(configurationFile, "r") as file:
        for line in file:
            username = line.strip()
            enableUser(username)


def disableUsers():
    if not os.path.isfile(configurationFile):
        sys.exit("ERROR: No configurazion file, please specify option -f ")
    with open(configurationFile, "r") as file:
        for line in file:
            username = line.strip()
            disableUser(username)

def UploadGroupAttributes():
    """Crea un gruppo contenente attributi"""
    validateConfigurationFile(3, "Group;AttributeKey;AttributeValue")
    with open(configurationFile, "r") as file:
        lines = file.readlines()[1:]
        for line in lines:
            if not (len(line.strip()) == 0):
                line_argument = line.split(";")
                group = line_argument[0].rstrip('\n')
                attribute_key = line_argument[1].rstrip('\n')
                attribute_value = line_argument[2].rstrip('\n')
                group_id = getGroup(group)

                if group_id == '':
                    print("Group:", group_id, "not present, creating ...")
                    addGroup(group)
                    group_id = getGroup(group)

                attribute = {
                    attribute_key : attribute_value
                }
                addMappingAttribute(group, group_id,attribute)

@handle_token
def disableUser(username):
    """Disable User"""
    try:
        ### GET ID OF USER
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env][
            'realmApp'] + "/users" + "?search=" + username
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, verify=ssl)
        user_result = response.json()
        if len(user_result) != 0:

            ### Disable USER
            url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env]['realmApp'] + "/users/" + \
                  user_result[0]['id']
            user_result[0]['enabled'] = False
            response = requests.put(url, json=user_result[0], headers=headers, verify=ssl)
            response.raise_for_status()
        else:
            print(username, "non è censito!")
    except:
        print("ERROR:", username, response.json()['errorMessage'])


@handle_token
def enableUser(username):
    """Enable User"""
    try:
        ### GET ID OF USER
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env][
            'realmApp'] + "/users" + "?search=" + username
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, verify=ssl)
        user_result = response.json()
        if len(user_result) != 0:

            ### ENABLE USER
            url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env]['realmApp'] + "/users/" + \
                  user_result[0]['id']
            user_result[0]['enabled'] = True
            response = requests.put(url, json=user_result[0], headers=headers, verify=ssl)
            response.raise_for_status()
        else:
            print(username, "non è censito!")
    except:
        print("ERROR:", username, response.json()['errorMessage'])


@handle_token
def createSystemUser():
    groups = getGroups()
    filename = str(user + "users.txt")
    with open(filename, 'w') as file:
        for group in groups:
            group_name = group['name']
            username = str(user + "_" + group_name)
            print(username)
            random_password = gen_password()
            BodyRequest = {
                'email': '',
                'emailVerified': 'false',
                'enabled': 'true',
                'firstName': username,
                'lastName': '',
                'username': username,
                'groups': [group_name],
                'credentials': [{
                    'temporary': 'false',
                    'type': 'password',
                    'value': random_password
                }]
            }
            url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env]['realmApp'] + "/users"
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            try:
                response = requests.post(url, json=BodyRequest, headers=headers, verify=ssl)
                response.raise_for_status()
                line = str(username + " " + random_password + "\n")
                file.write(line)
                print("User ", username, "created!")
            except requests.exceptions.HTTPError as e:
                if e.response.status_code != 401:
                    print("ERROR:", username, response.json()['errorMessage'])
                else:
                    raise

@handle_token
def exportUsers():
    """Export Users"""
    try:
        content = []
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env][
            'realmApp'] + "/users"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, verify=ssl)
        user_result = response.json()
        for item in user_result:
            user_id = item['id']

            name = ""
            lastname = ""
            email = ""
            groups = ""
            name = item.get('firstName')
            lastname = item.get('lastName')
            email = item.get('email')
            groups = getUserGroups(user_id)


            user = {
                'firstName': name,
                'lastName': lastname,
                'email': email,
                'groups': ",".join(groups)
            }
            content.append(user)
            print(user)
        write_csv(content)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 401:
            print("ERROR:", response.json()['errorMessage'])
        else:
            raise

@handle_token
def getUserGroups(id):
    try:
        url = config[customer][env]['baseurl'] + "/admin/realms/" + config[customer][env][
            'realmApp'] + "/users/" + id + "/groups"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, verify=ssl)
        result = response.json()
        groups = []
        for item in result:
            groups.append(item['name'])
        return groups
    except:
        print("ERROR:", response.json()['errorMessage'])

def validateConfigurationFile(column, description):
    ### CHECK FILE
    if not os.path.isfile(configurationFile):
        sys.exit("ERROR: No configurazion file, please specify option -f ")
    with open(configurationFile, "r") as file:
        lines = file.readlines()[1:]
        for line in lines:
            ### skippa le linee vuote
            if not (len(line.strip()) == 0):
                line_argument = line.split(';')
                # clean_argument = []
                # for element in line_argument:
                #     clean_endline = element.rstrip('\n')
                #     if clean_endline:
                #         clean_argument.append(clean_endline)
                ### verifico che il numero dei campi sia del numero desiderato
                if not len(line_argument) == column:
                    sys.exit("FILE ERROR:" + str(
                        column) + " columns must be present \nPlease, follow this format: " + description)

# MAIN
customer, env, password, opt, configurationFile, user = getInput()

if config[customer][env]['ssl'] == 'False':
    ssl = False
else:
    ssl = True
getToken()  # Ottieni il primo token

match opt:
    case 'downloadGroupAndRole':
        downloadGroupAndRole()
    case 'UploadGroupAndRole':
        UploadGroupAndRole()
    case 'UploadGroupAttributes':
        UploadGroupAttributes()
    case 'UploadUsers':
        UploadUsers()
    case 'EnableUsers':
        enableUsers()
    case 'disableUsers':
        disableUsers()
    case 'createSystemUser':
        createSystemUser()
    case 'exportUsers':
        exportUsers()
