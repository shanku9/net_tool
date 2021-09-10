from flask import Flask, render_template, request,Response, redirect, url_for, flash
from nornir import InitNornir
import csv
import sys
import ipapi
from tabulate import tabulate
from nornir.plugins.functions.text import print_result, print_title
from nornir.plugins.tasks.networking import netmiko_send_config, netmiko_send_command
import pandas as pd
from nornir.plugins.tasks.files import write_file
from nornir.core.filter import F
from datetime import datetime
import pathlib
from scapy.all import *
import base64
from scapy.layers.inet import traceroute
import graphviz
import ipaddress
import os
import yaml

from datetime import date
from nornir.plugins.tasks import networking

app = Flask(__name__)
#app.secret_key = "Secret Key"
app.config['SECRET_KEY']='imranawan'

#Class for CSV TO YAML////////////////////////
class Csv2NornirSimple:

    def __init__(self, filename):
        self.filename = filename
        self.inventory_data = []

    def inventory_converter(self):
        inventory_list = []
        # Currently not in use

        try:
            with open(self.filename) as csv_file:
                csv_reader = csv.DictReader(csv_file)
                for row in csv_reader:
                    inventory_list.append([
                        row["name"],
                        row["hostname"],
                        row["platform"],
                        row["port"],
                        row["username"],
                        row["password"],
                        row["secret"],
                        row["groups"],
                        row["secret"],



                    ])
                self.inventory_data = inventory_list
        except FileNotFoundError:
            print(f"Please make sure that filename is correct and exists...")
            sys.exit(1)


    # Iterates over the list and creates the csv_inventory.yaml based on the Nornir model

    def make_nornir_inventory(self):
        if len(self.inventory_data) < 1:
            print("The list argument doesn't have any records! Cannot create an inventory file out of an empty list!")
            return ValueError
        try:

            with open("csv_inventory.yaml", "w") as out_file:
                out_file.write("---\n")
                for host in self.inventory_data:
                    out_file.write(f"{host[0]}:\n")
                    out_file.write(f"  hostname: {host[1]}\n")
                    out_file.write(f"  platform: {host[2]}\n")
                    out_file.write(f"  port: {host[3]}\n")
                    out_file.write(f"  username: {host[4]}\n")
                    out_file.write(f"  password: {host[5]}\n")
                    out_file.write(f"  secret: {host[6]}\n")

                    if len(host[7].split("_")) > 0:
                        out_file.write(f"  groups:\n")
                        for group in host[7].split("__"):
                            out_file.write(f"    - {group}\n")

                    else:
                        out_file.write("\n")
                    out_file.write(f"  connection_options:\n")
                    out_file.write(f"    napalm:\n")
                    out_file.write(f"      extras:\n")
                    out_file.write(f"        optional_args:\n")
                    out_file.write(f"          secret: {host[8]}\n")




                print("Inventory file created...")
        except PermissionError:
            print("An error occurred whilst trying to write into the file... Please make sure that there are enough permission assigned to the user executing the script...")
            sys.exit(1)


csv2n = Csv2NornirSimple("inventory.csv")
inventory_list = csv2n.inventory_converter()
csv2n.make_nornir_inventory()

# Verify that the inventory file is readable

nr = InitNornir(inventory={"plugin": "nornir.plugins.inventory.simple.SimpleInventory", "options": {"host_file": "csv_inventory.yaml"}})
#//////////////////////////////////////////////

#Home Page////////////////////////////////////
@app.route('/')
def home():


    return render_template("home.html")


#/////////////////////////////////////////////

#///////////////////////////////////BackupConfig///////////////////
@app.route('/backup', methods = ['GET', 'POST'])
def backup():

    #command = request.form.get('command')
    groupname = request.form.get('backup')


    try:

        def backup_configurations(task):
            config_dir = "config-archive"
            device_dir = config_dir + "/" + task.host.name
            pathlib.Path(config_dir).mkdir(exist_ok=True)
            pathlib.Path(device_dir).mkdir(exist_ok=True)
            r = task.run(task=networking.napalm_get, getters=["config"])
            task.run(task=write_file,content=r.result["config"]["running"],
             filename=f"" + str(device_dir) + "/" + str(date.today()) + ".txt",)
        hosts=nr.filter(F(groups__contains=groupname))
        record=hosts.run(name="Creating Backup Archive", task=backup_configurations)
        results=nr.data.failed_hosts
        l=len(nr.data.failed_hosts)



    except:
            print(' Make sure GroupName is OK.')


    return render_template('backup.html',  results=results,l=l)
#///////////////////////////////////////////////////////////////////
#///////////////////////////////////BackupConfigbyCommands///////////////////
@app.route('/backup1', methods = ['GET', 'POST'])
def backup1():
    results=''
    l=''
    command1 = request.form.get('command1')
    groupname1 = request.form.get('backup1')


    try:

        def backup_configurations(task):
            config_dir = "config-archive"
            device_dir = config_dir + "/" + task.host.name
            pathlib.Path(config_dir).mkdir(exist_ok=True)
            pathlib.Path(device_dir).mkdir(exist_ok=True)
            r = task.run(task=netmiko_send_command, command_string = command1)
            task.run(task=write_file,content=r.result,
                     filename=f"" + str(device_dir) + "/" + str(date.today()) + ".txt",)
        hosts=nr.filter(F(groups__contains=groupname1))
        record=hosts.run(name="Creating Backup Archive", task=backup_configurations)



    except:
        print(' Make sure GroupName is OK.')


    return render_template('backup.html',  results=nr.data.failed_hosts,l=len(nr.data.failed_hosts))


#///////////////////////////////////////////////////////////////////

#/INDEXhtml/////////////////////////////////////////////////////////////////
def load_hosts_inventory(filename):
    return yaml.load(open(filename, "r"), Loader=yaml.SafeLoader)
hosts = load_hosts_inventory("csv_inventory.yaml")
# print(hosts)
inventory = []
for host in hosts:
    inventory.append({"name": host, "mgmt_ip": hosts[host]["hostname"], "platform": hosts[host]["platform"]})

@app.route('/index', methods = ['GET', 'POST'])
def index():

    return render_template("index.html", inventory = inventory)

#//////////////////////////////////////////////////////////////////////////
#///////////Factshtml/////////////////////////////////////////////////////
def get_facts(device):
    nr = InitNornir(inventory={"plugin": "nornir.plugins.inventory.simple.SimpleInventory", "options": {"host_file": "csv_inventory.yaml"}})
    nrfil = nr.filter(name=device)
    results = nrfil.run(
        task=networking.napalm_get,
        getters=["facts", "interfaces","arp_table","interfaces_counters"]
    )
    return results[device][0].result
@app.route('/facts/<string:device_name>' , methods = ['GET', 'POST'])
def display_facts(device_name):
    facts = get_facts(device_name)

    arp_list= []
    for arp in facts["arp_table"]:
        arp_list.append(arp)
    ios_output2=facts["interfaces_counters"]



    device_interface_list = []
    for interface in facts["facts"]["interface_list"]:
        device_interface_list.append({"name": interface,
                                      "enabled":  facts["interfaces"][interface]["is_enabled"],
                                      "up": facts["interfaces"][interface]["is_up"],
                                      "description": facts["interfaces"][interface]["description"],
                                      "mac": facts["interfaces"][interface]["mac_address"],
                                      "mtu": facts["interfaces"][interface]["mtu"],
                                      "speed": facts["interfaces"][interface]["speed"],
                                      "last_flapped": facts["interfaces"][interface]["last_flapped"]
                                      })

    return render_template("facts.html", device_name=device_name, facts=facts,
                           interface_list=device_interface_list,arp_list=arp_list,ios_output2=ios_output2)
#////////////////////////////////////////////////////////////////////////

#/////////////////////////SaveShowCommandOutPutbyGroup/////////////////////////
@app.route('/saveshowcommand', methods=['GET', 'POST'])
def saveshowcommand():

    group = request.form.get('group')
    command=request.form.get('command')

    def show_configurations(task):
        config_dir = "ShowCommand-archive"
        date_dir = config_dir + "/" + str(date.today())
        command_dir = date_dir + "/" + command
        pathlib.Path(config_dir).mkdir(exist_ok=True)
        pathlib.Path(date_dir).mkdir(exist_ok=True)
        pathlib.Path(command_dir).mkdir(exist_ok=True)
        r = task.run(task=netmiko_send_command, command_string=command)
        task.run(task=write_file,content=r.result,
            filename=f"" + str(command_dir) + "/" + task.host.name + ".txt",
        )
    nr = InitNornir(inventory={"plugin": "nornir.plugins.inventory.simple.SimpleInventory", "options": {"host_file": "csv_inventory.yaml"}})
    hosts=nr.filter(F(groups__contains=group))

    result = hosts.run(name="Creating Show Command Backup Archive", task=show_configurations)

    return render_template('saveshowcommand.html',results=nr.data.failed_hosts,l=len(nr.data.failed_hosts) )


#///////////////////////////////////SaveShowCommandOutPutbyName///////////////////////////////////
@app.route('/saveshowcommand1', methods=['GET', 'POST'])
def saveshowcommand1():

    name = request.form.get('group1')
    command1=request.form.get('command1')

    def show_configurations(task):
        config_dir = "ShowCommand-archive"
        date_dir = config_dir + "/" + str(date.today())
        command_dir = date_dir + "/" + command1
        pathlib.Path(config_dir).mkdir(exist_ok=True)
        pathlib.Path(date_dir).mkdir(exist_ok=True)
        pathlib.Path(command_dir).mkdir(exist_ok=True)
        r = task.run(task=netmiko_send_command, command_string=command1)
        task.run(task=write_file,content=r.result,
                 filename=f"" + str(command_dir) + "/" + task.host.name + ".txt",
                 )
    nr = InitNornir(inventory={"plugin": "nornir.plugins.inventory.simple.SimpleInventory", "options": {"host_file": "csv_inventory.yaml"}})
    hosts=nr.filter(F(name__contains=name))

    result = hosts.run(name="Creating Show Command Backup Archive", task=show_configurations)

    return render_template('saveshowcommand.html',  results=nr.data.failed_hosts,l=len(nr.data.failed_hosts))


#//////////////////////////////////////////////////////////////////////
#///////////////////////configfile////////////////////////////
@app.route('/fileconfig', methods=['GET','POST'])
def fileconfig():
    input_days = ''
    if request.method == 'POST':
        input_days = request.form['textbox']
        with open('config_textfile', 'w') as f:
            f.write(str(input_days))
    return render_template('fileconfig.html', days=input_days)

#/////////////////////////////////////////////////////////////
#///////////////////////////////Automation///////////////////////////////////
@app.route('/automate', methods = ['GET', 'POST'])
def automate():

    g=request.form.get('config')
    hosts=nr.filter(F(groups__contains=g))
    def automate1(job):
        job.run(task=netmiko_send_config, config_file= "config_textfile")
    results = hosts.run(task = automate1)

    return render_template('automate.html',results=nr.data.failed_hosts,l=len(nr.data.failed_hosts))
#////////////////////////////////////////////////////////////////////////////////////
#///////////////////////////////SaveRunningConfig///////////////////////////////////
@app.route('/configsave', methods = ['GET', 'POST'])
def configsave():

    command=request.form.get('command')
    c = request.form.get('group')
    hosts=nr.filter(F(groups__contains=c))
    def automate(job):
        job.run(task=netmiko_send_command, command_string = command)
    results = hosts.run(task = automate)

    return render_template('configsave.html', results=nr.data.failed_hosts,l=len(nr.data.failed_hosts))
#//////////////////////////////////////////////////////////////////////////
#/////////////////////////////////// IP FINDER //////////////////////

@app.route('/ipfinder', methods = ['GET', 'POST'])
def ipfinder():
    data=[]
    try:
        data = ipapi.location(ip=request.form.get('search'), output='json')
        print(data)
    except:
        print('Not valid')
    return render_template('ipfinder.html', data=data)

#//////////////////////////// IPADDRESS////////////////////////////////////////
@app.route('/ipaddress', methods=['GET','POST'])
def ipaddr():
    try:
        p = []
        ip = request.form.get('ip')
        print(ip)
        p.append("IP Enter is "+ip)

        net4 = ipaddress.ip_network(ip)
        p.append("Prefix is :")
        p.append(net4.prefixlen )
        p.append("Subnetmask is :")
        p.append(net4.netmask)
        p.append("Total IPs is :")
        p.append(net4.num_addresses)
        p.append("Broadcast is :")
        p.append(net4.broadcast_address)
        p.append("First SubNetwork :")
        for x in net4.subnets():
            p.append(x)


    except:
        print("No")

    return render_template('ipaddress.html', len=len(p), p=p)


#//////////////////////////////////////////////////////////////////

#//////////////////////////// COMMANDER////////////////////////////////////////
@app.route('/commander', methods=['GET','POST'])
def commander():
  z=''

  try:
    command = request.form.get('command')
    name =   request.form.get('name')
    hosts=nr.filter(name=name)
    results = hosts.run(task=netmiko_send_command, command_string=command )
    z=results[name][0]
    results=''
    l=''

  except:
      print("Fail to Print")
  return render_template('commander.html',results=nr.data.failed_hosts,l=len(nr.data.failed_hosts),z=z)


#//////////////////////////////////////////////////////////////////
#//////////////////////////////////////Traceroute////////////////////////////////////////

@app.route('/trace/<string:ip>' , methods = ['GET', 'POST'])
def trace(ip):

    os.remove("./static/traceroute_graph.svg")
    hosts = [ip]    
    res,unans = traceroute(hosts)
    res.graph(target=">./static/traceroute_graph.svg")
    return render_template('traceroute.html',ip=ip)

#///////////////////////////////////////////////////////////////////////////////////////

if __name__ == "__main__":
    app.run(host="0.0.0.0",debug=True )