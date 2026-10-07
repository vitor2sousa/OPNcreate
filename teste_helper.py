from opnsense_helper.opnsense_helper import Opnsense_Helper
import getpass

senha = getpass.getpass("Senha do root do OPNsense: ")

helper = Opnsense_Helper(
    host="177.10.1.241",
    ssh_auth={"user": "root", "passw": senha},
    temp_path="./config.xml"
)

print("Conexão OK — config.xml baixado")