import tkinter as tk
from tkinter import *
from tkinter import messagebox
from tkinter.ttk import *
from tkinter import messagebox
from tkinter.ttk import Progressbar
from tkinter import ttk
from tkinter import filedialog
from tkinter.filedialog import askopenfile 
from os import path
from functools import partial
import requests
import time, threading
from operator import itemgetter
##from apscheduler.scheduler import Scheduler
from apscheduler.schedulers.background import BackgroundScheduler


##Window label and title
window = tk.Tk()
window.title("Automate Firmware Upgrade for SEL SDN Switches")
window.geometry('555x260')
window.resizable(0,0)

NodeDisplayNamesList = []
NodeDisplayNamesList_Adopted = []
NodeDisplayNamesList_nodeType = []
#------
#username label and text entry box
usernameLabel = Label(window, text="Username")
usernameLabel.place(x=30,y=40)
passwordLabel = Label(window,text="Password")
passwordLabel.place(x=156,y=40)
domainNameLabel = Label(window,text="Host Name")
domainNameLabel.place(x=282,y=40)
portNumberLabel = Label(window,text="Port Number")
portNumberLabel.place(x=408,y=40)


#password label and password entry box
username = StringVar()
usernameEntry = Entry(window, textvariable=username)
usernameEntry.place(x=30,y=60)
                    
password = StringVar()
passwordEntry = Entry(window, textvariable=password, show='*')
passwordEntry.place(x=156,y=60)

domainname = StringVar()
domainnameEntry = Entry(window, textvariable=domainname)
domainnameEntry.place(x=282,y=60)

port = StringVar()
portEntry = Entry(window, textvariable=port)
portEntry.place(x=408,y=60)

##---------------Login Credentials frame
##Validate ACCESS TOKEN 
def validateAccessToken(username, password, domainname, port):
##        print("validateAccessToken","username",username.get(),"Password",password.get())
        url_access_token = "https://"+domainname.get()+":"+port.get()+"/identity/connect/token"
##        body_token = 'grant_type=password&username=munja&password=Pass@12345&client_secret=Rest%20Interface&client_id=password-client&state=0&acr_values=role%3APermissionLevel3'
        body_token = 'grant_type=password&username='+username.get()+'&password='+password.get()+'&client_secret=Rest%20Interface&client_id=password-client&state=0&acr_values=role%3APermissionLevel3'
        headers_token = {  'Content-Type': 'application/x-www-form-urlencoded'}
        if (len(domainname.get()) == 0):
                url_access_token = "https://localhost/identity/connect/token"        
                response_token = requests.request("POST", url_access_token, headers=headers_token, data = body_token, verify=False)
##                print("---Response_token", response_token)
        else:             
                response_token = requests.request("POST", url_access_token, headers=headers_token, data = body_token, verify=False)
        return response_token

#Validate Username, password to login
def validate_Login(username, password, domainname, port):
        if len(domainname.get()) < 0 or (len(port.get()) < 0):
                messagebox.showinfo("Please enter all ogin credentials.","Please enter all login credentials!")
        else:
                print("-----78---------",len(domainname.get()))
                response_login_check = validateAccessToken(username, password, domainname, port)
                print("response_login_check",response_login_check)                
                if response_login_check.status_code == 200:
                        messagebox.showinfo("Login validation screen","Login is successful")
                else:
                        messagebox.showinfo("Login validation screen","Error! Please check Login Credentials and Try again. ")
                return response_login_check

login_title=Label(window,text="Login Credentials",font=("Arial Bold",10))
login_title.place(x=30,y=15)
    
validate_Login = partial(validate_Login, username, password, domainname, port)

#login button
loginButton = Button(window, text="Login", command=validate_Login)
loginButton.place(x=110,y=90)

##print("username entered :", username.get())
##print("password entered :", password.get())

##---------------Select SEL device Check button option------------------------------
Selectlabel = tk.Label(text="SDN Switch Model Filter",font=("Arial Bold",10))
Selectlabel.place(x=30,y=120)
##Check Button SEL-2740S and SEL-2742S
chkbtn1 = IntVar()
chkbtn2 = IntVar()
chk2740 = Checkbutton(window,text='SEL-2740S',  onvalue = 1, offvalue = 0, variable=chkbtn1)
chk2742 = Checkbutton(window,text='SEL-2742S',  onvalue = 1, offvalue = 0, variable=chkbtn2)

##Open file function
def open_file():
        global FWfile
        FWfile = filedialog.askopenfile(filetypes=[('Firmware file', '*.gz')])

files = ""

chk2740.place(x=40,y=140)
chk2742.place(x=150,y=140)
##------------------Firmware Upgrade for SEL Switches label------------------------------------

##FWlabel = tk.Label(text="Submit for Firmware Upgrade of SEL Switches", font=("Arial Bold",10))
##FWlabel.place(x=30,y=190)

"Firmware_Upgrade function initiates the firmware upgrade process for the selected switches between SEL-2740S and SEL-2742S "
def Firmware_Upgrade(username,password, domainname, port):
        ##---------------------Get Access token-------------------------------
        global fname1
        global fname2  
        response_FW_upgrade = ""

##        print('Get Access token')
        response_access_token2 = validateAccessToken(username,password, domainname, port)
        token1 = response_access_token2.json()
        token2 = token1.get('access_token')
##        print('Access TOKEN is', token2)

        ##---------------------Read Operational Nodes-------------------------------
##        print('Read Operational Nodes')
        url_get_operational_nodes = "https://"+domainname.get()+":"+port.get()+"/api/default/operational/nodes?$filter=attributes/any(t: isof(t, 'Sel.Sel5056.TopologyManager.Attributes.Operational.Node.SelSapphireAttr'))"

        if (token2):
                body_operational_nodes = {}
                files_operational_nodes = {}
                headers_operational_nodes = {"Authorization": 'Bearer' + token2,   'Content-Type': 'application/json'}
                response_operational_nodes = requests.get(url_get_operational_nodes, headers = {"Authorization": 'Bearer ' + token2,'Content-Type': 'application/json'}, data = body_operational_nodes, files = files_operational_nodes, verify=False)
        if chkbtn1.get()==1 and chkbtn2.get()==0:
##                print("1,0")
                messagebox.showinfo("Select Firmware File for SEL2740S","Select Firmware File for SEL2740S")
                fname1 = filedialog.askopenfilename(filetypes=[('Firmware file', '*.gz')])
        elif chkbtn1.get()==0 and chkbtn2.get()==1:
##                print("0,1")
                messagebox.showinfo("Select Firmware File for SEL2742S","Select Firmware File for SEL2742S")
                fname2 = filedialog.askopenfilename(filetypes=[('Firmware file', '*.gz')])
        elif chkbtn1.get()==1 and chkbtn2.get()==1:
##                print("1,1")
                messagebox.showinfo("Select Firmware File for SEL2740S","Select Firmware File for SEL2740S")
                fname1 = filedialog.askopenfilename(filetypes=[('Firmware file', '*.gz')])
                messagebox.showinfo("Select Firmware File for SEL2742S","Select Firmware File for SEL2742S")
                fname2 = filedialog.askopenfilename(filetypes=[('Firmware file', '*.gz')])
        elif chkbtn1.get()==0 and chkbtn2.get()==0:
##                print("0,0")
                messagebox.showinfo("Select atleast one switch to procceed","Select atleast one switch to procceed")
##                print("Please select atleast one switch between two for firmware upload process")
        ##--------------------Look for the nodes and do Firmware Upgrade--------------------------------
        if (token2):
                node_id = response_operational_nodes.json()
                node2 = node_id.get('value')
                progress_bar["value"] = 5
##                print("type(node2)",type(node2))

        def get_nodes(switch_nodes):
                swicth_id = []
                for n in switch_nodes:
##                        print(switch_nodes)
##                        print("-------",len(n))
##                        print(n["state"])
                        temp_id = n["state"]
                        checkifswicth_flag = n["displayName"]
                        if temp_id =="Adopted":
                                NodeDisplayNamesList.append(checkifswicth_flag)
                                                
                        for m in n["attributes"]:
##                                print(len(m))
                                if (m.get("nodeType") == "Sel2740S" or "Sel2742S")and checkifswicth_flag != "Controller" and (chkbtn1.get()==1 or chkbtn2.get()==1) and (n["state"]=="Adopted"):
                                        CheckSwitchType = m.get("nodeType")
                                        NodeDisplayNamesList_nodeType.append(m.get("nodeType"))
                                        ##
##                                        if chkbtn1.get()==1 and chkbtn2.get()==0 and CheckSwitchType == "Sel2740S":
##                                                NodeDisplayNamesList.append(m.get("nodeType"))
##                                                print("NodeDisplayNamesList--first",NodeDisplayNamesList)
##                                        if chkbtn1.get()==0 and chkbtn2.get()==1 and (m.get("nodeType") == "Sel2742S"):
##                                                NodeDisplayNamesList.append(checkifswicth_flag)
##                                        if chkbtn1.get()==1 and chkbtn2.get()==1:
##                                                NodeDisplayNamesList.append(checkifswicth_flag)
##                                        if m.get("state")=="Success":
##                                                NodeDisplayNamesList_Adopted.append(n["displayName"])
##                                        print("NodeDisplayNamesList_Adopted--",NodeDisplayNamesList,NodeDisplayNamesList_Adopted)
                                        
##                                        if chkbtn1.get()==1 and chkbtn2.get()==0 and m.get("nodeType") != "Sel2740S":
##                                                messagebox.showerror("Error", "Selected to upgrade SEL-2740S switch, but SEL-2742S switch can not found in the network")
##                                                progress_bar["value"] = 0
##                                                return token2
##                                        if chkbtn1.get()==0 and chkbtn2.get()==1 and m.get("nodeType") != "Sel2742S":
##                                                messagebox.showerror("Error", "Selected to upgrade SEL-2742S switch, but SEL-2742S switch can not found in the network")
##                                                progress_bar["value"] = 0
##                                                return token2
                                        ##                                        
                                        
##                                        print(CheckSwitchType)
                                        if temp_id == "Adopted" and checkifswicth_flag != "Controller":
##                                                print('Firmware Upgrade')
                                                switch_id_for_FWUpdate = n["id"]
                                                url_FW_Upgrade = "https://"+domainname.get()+":"+port.get()+"/api/default/operational/nodes('"+switch_id_for_FWUpdate+"')/FirmwareUpgrade"
                                                url_FW_Upgrade_status = "https://"+domainname.get()+":"+port.get()+"/api/default/operational/nodes('"+switch_id_for_FWUpdate+"')"
##                                                print(url_FW_Upgrade)
                                                progress_bar["value"] = 15
                                                progress_bar.update()
                                                
                                                if CheckSwitchType == "Sel2742S" and chkbtn2.get()==1:
                                                        response_FW_upgrade = requests.post(url_FW_Upgrade, headers = {"Authorization": 'Bearer ' + token2}, files = {"fileName": open(fname2, "rb").read()}, verify=False)
                                                        response_FW_upgrade2 = requests.get(url_FW_Upgrade_status, headers = {"Authorization": 'Bearer ' + token2}, verify=False)
                                                        messagebox.showinfo("Firmware upload Percentage Complete status",response_FW_upgrade2)
##                                                        print(response_FW_upgrade)
##                                                        print(response_FW_upgrade2)
                                                elif CheckSwitchType == "Sel2740S" and chkbtn1.get()==1:
##                                                        print("Hello")
                                                        response_FW_upgrade = requests.post(url_FW_Upgrade, headers = {"Authorization": 'Bearer ' + token2}, files = {"fileName": open(fname1, "rb").read()}, verify=False)
                        progress_bar["value"] = 25
##                        print("NodeDisplayNamesList_Adopted--",NodeDisplayNamesList_Adopted)
                progress_bar["value"] = 30
                progress_bar.update()
##                print("NodeDisplayNamesList",NodeDisplayNamesList)
##                return NodeDisplayNamesList
        progress_bar["value"] = 40
        progress_bar.update()
        if((token2) and (response_access_token2.status_code == 200) and (chkbtn1.get()==1 or chkbtn2.get()==1)):
            a_id = get_nodes(node2)
##            print('Firmware Upgrade is Done.!')
##        FirmwareUpgradeProgressTable(token2)
        return token2


"FirmwareUpgradeProgressBar function"
def FirmwareUpgradeProgressTable(token2):
##        print("token2",token2)
        url_get_operational_nodes = "https://"+domainname.get()+":"+port.get()+"/api/default/operational/nodes?$filter=attributes/any(t: isof(t, 'Sel.Sel5056.TopologyManager.Attributes.Operational.Node.SelSapphireAttr'))"

        if (token2):
                body_operational_nodes = {}
                files_operational_nodes = {}
                headers_operational_nodes = {"Authorization": 'Bearer' + token2,   'Content-Type': 'application/json'}
                response_operational_nodes = requests.get(url_get_operational_nodes, headers = {"Authorization": 'Bearer ' + token2,'Content-Type': 'application/json'}, data = body_operational_nodes, files = files_operational_nodes, verify=False)
        if (token2):
                node_id = response_operational_nodes.json()
                node2 = node_id.get('value')
##                print("node2",node_id)
        global stopThreadTimer
        global ping_thread
        global Timerthreadstartflag
        
        
        progress_barFinal = False
        stopThreadTimerFlag = False
        ping_thread = threading.Timer(1, FirmwareUpgradeProgressTable,(token2,))
        ping_thread.setDaemon(True)
        ping_thread.start()
        "check each node"
        for n in node2:
##                print(n,"------len(n)-------------------------------------------------------------",len(n))
                node_state = n["state"]
                checkifswicth_flag = n["displayName"]
                for m in n["attributes"]:
##                        print("--------len(m)-----------------------------------------------------------",len(m))
                        if (node_state == "Adopted") and checkifswicth_flag != "Controller" and chkbtn1.get()==1 or chkbtn2.get()==1:
                                if (m.get("nodeType") == "Sel2740S" or "Sel2742S") and (m.get("firmwareFileUploadPercentComplete") is not None):
##                                        print(NodeDisplayNamesList)
                                        if chkbtn1.get()==1 and chkbtn2.get()==0:
                                                if "Sel2740S" not in NodeDisplayNamesList_nodeType:
                                                        ping_thread.cancel()
                                                        messagebox.showerror("Error", "Selected to upgrade SEL-2740S switch, but can not found in the network")
                                                        progress_bar["value"] = 0
##                                                        print("not found 2740")
                                                        return stopThreadTimerFlag
                                                
                                        if chkbtn1.get()==0 and chkbtn2.get()==1:
                                                if "Sel2742S" not in NodeDisplayNamesList_nodeType:
                                                        ping_thread.cancel()
                                                        messagebox.showerror("Error", "Selected to upgrade SEL-2742S switch, but can not found in the network")
                                                        progress_bar["value"] = 0
##                                                        print("not found 2742")
                                                        return stopThreadTimerFlag
                                        if chkbtn1.get()==1 and chkbtn2.get()==1:
                                                if "Sel2740S" not in NodeDisplayNamesList_nodeType and "Sel2742S" not in NodeDisplayNamesList_nodeType:
                                                        ping_thread.cancel()
                                                        messagebox.showerror("Error", "Selected to upgrade switch, but can not found in the network")
                                                        progress_bar["value"] = 0
##                                                        print("not found 2740S and Sel2742S")
                                                        return stopThreadTimerFlag
                                        
                                        if len(NodeDisplayNamesList) !=0: 
                                                if n["displayName"] == NodeDisplayNamesList[-1]:
                                                                
##                                                        print("--- Node Display List-",NodeDisplayNamesList,n["displayName"],"---Upload%",m.get("firmwareFileUploadPercentComplete"),"---FWStatus",m.get("firmwareUploadDeviceStatus"))
##                                                        print("progress_barFinal",progress_barFinal,"---stopThreadTimerFlag",stopThreadTimerFlag)
                                                        if m.get("firmwareFileUploadPercentComplete")>0 and m.get("firmwareFileUploadPercentComplete")<=50:
                                                                progress_bar["value"] = 50
                                                        if m.get("firmwareFileUploadPercentComplete")>=51 and m.get("firmwareFileUploadPercentComplete")<100:
                                                                progress_bar["value"] = 55
                                                        if m.get("firmwareUploadDeviceStatus") == "Step 3 of 6: Verifying signature":
                                                                progress_bar["value"] = 60                                                                
                                                        if m.get("firmwareUploadDeviceStatus") == "Step 4 of 6: Preparing upgrade":
                                                                progress_bar["value"] = 65
                                                        if m.get("firmwareUploadDeviceStatus") == "Step 5 of 6: Running upgrade":
                                                                progress_bar["value"] = 75
                                                                progress_barFinal=True
                                                        if m.get("firmwareUploadDeviceStatus") == "Step 6 of 6: Cleaning up":
                                                                progress_bar["value"] = 80
                                        else:
                                                progress_bar["value"] = 0
                                                ping_thread.cancel()
                        if (m.get("firmwareUploadDeviceStatus") == "Firmware upgrade succeeded" and m.get("firmwareFileUploadPercentComplete") == 100 and progress_barFinal==True):
                                progress_bar["value"] = 90
                                stopThreadTimerFlag = True
        
        if stopThreadTimerFlag == True:
##                print("stopped threading.Timer")
                ping_thread.cancel()
                progress_bar["value"] = 100
                messagebox.showinfo("List of Devices for Firmware Upgrade",NodeDisplayNamesList)
                return stopThreadTimerFlag
               
        return stopThreadTimerFlag


##Firmware Upgrade Click button function
def Click_Button():
        NodeDisplayNamesList.clear()
        Check_response_access_token = validateAccessToken(username,password, domainname, port)
        if (Check_response_access_token.status_code == 200):
                if (chkbtn1.get()==1 or chkbtn2.get()==1):
                        messagebox.showinfo("Firmware Upgrade initiated","Firmware Upgrade initiated")
                        "Call function Firmware_Upgrade to initiate Firmware upgrade process"
                        
                        token2 = Firmware_Upgrade(username,password, domainname, port)

                        progress_bar["value"] = 40
                        progress_bar.update()
                        ping_thread = None
                        stopThreadTimerFlag = None
                        Timerthreadstartflag =  0
                        "FirmwareUpgradeProgressTable updates the progressbar for Firmware upgrade"
                        stopThreadTimerFlag = FirmwareUpgradeProgressTable(token2)
##                        print(stopThreadTimerFlag)              
                else:
                        messagebox.showinfo("Alert message","Select atleast one switch to procceed")
        else:
            messagebox.showinfo("Login validation screen","Error! Can not proceed! Please check Login Credentials to SDN Flow Controller and Try Again.") 

##Window Firmware Upgrade Click button
button = tk.Button(window,text="Begin Firmware Upgrade ",font=("Arial Bold",12), width=25, bg="green",fg="white",command=Click_Button)
button.place(x=40,y=170)

# Create a progressbar widget
percent = StringVar()
progress_bar = ttk.Progressbar(window, orient="horizontal", mode="determinate", length=200)                      
progress_bar.pack(fill=X,expand=1)
# And a label for it
label_1 = tk.Label(window, text="Firmware Upgrade Progress Bar :", font=("Arial Bold",10))
# Use the grid manager
label_1.place(x=30,y=230)
progress_bar.place(x=250, y=230)
        

##Window mainloop       
window.mainloop()
##--------------------------------------------------------------------------------------------------------------------------





