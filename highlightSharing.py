from burp import IBurpExtender, ITab
import time
from burp import IContextMenuFactory, IBurpExtenderCallbacks, IRequestInfo,IExtensionStateListener
from javax.swing import JPanel, JLabel, JTextField, SwingConstants, JButton,JList, JCheckBox
from com.ziclix.python.sql import zxJDBC
from java.net.http import HttpClient;
from java.net.http import WebSocket
from java.net import URI;
import java.lang.CharSequence
import json


class BurpExtender(IBurpExtender,IContextMenuFactory,ITab, IRequestInfo, IBurpExtenderCallbacks,IExtensionStateListener, WebSocket.Listener):

    def __init__(self):
        self.debugging=False
        self.version="v2.0"
        self._scheme = True
        self._domain = True
        self._path = True
        self._query = False
        self._projectNames = ()
        self._websocket=None

    ##### WEBSOCKET PART ######

    def onOpen(self, websocket):
        self._websocket=websocket
        data={"action":"LIST"}
        if not self.sendMessage(json.dumps(data)):
            self.writeText("Not connected: Failed to connect to the websocket server")
        self._websocket.request(1)
        self.writeText("Connected")
        self._projectNames = ()

    def onClose(self, websocket, statusCode, reason):
        self.writeText("Not connected: connection closed")

    def onText(self, websocket, data, last):
        if self.debugging:
            self._callbacks.printOutput("Received message")
        self._websocket=websocket
        content = json.loads(data.toString())
        if "name" in content.keys():#updating list before choosing a project
            self._projectNames+=(content["name"],)
            self._projectList.setListData(self._projectNames)
            self._websocket.request(1)
            return

        user = content["user"]
        project = content["projectname"]
        if user != self._user and project == self._projectName and content["value"] != "":
            if self.debugging:
                self._callbacks.printOutput("Updating URL: "+content["value"])
            self.updateReq(content["type"], content["value"], content["color"], content["comment"])
        elif self.debugging:
            self._callbacks.printOutput("NOT UPDATING URL: "+content["value"])
        self._websocket.request(1)

    def sendMessage(self, text):
        if self.debugging:
            self._callbacks.printOutput("Sending message")
        if self._websocket:
            self._websocket.sendText(text, True)
            self._websocket.request(1)
            if self.debugging:
                self._callbacks.printOutput("Message sent")
            return True
        return False # is probably not initialized, due to some async thingy......


    def connectWebsocket(self, event):
        if self.debugging:
            self._callbacks.printOutput("connecting")
        self.writeText("Not connected")
        self._wsString = self._wsStringButton.getText()
        self._user = self._userButton.getText()
        if self._wsString == "" or self._user == "":
            self.writeText("Not connected: Please specify a username and ws string")
            return
        client = HttpClient.newHttpClient()
        client.newWebSocketBuilder().buildAsync(URI.create(self._wsString),  self)
        


    def writeText(self, connection):
        if self.debugging:
            self._messageBox.text=connection+" and debugging enabled"
        else:
            self._messageBox.text=connection

    def selectProject(self, var2):
        self._projectName = self._projectList.getSelectedValue()
        if self.debugging:
            self._callbacks.printOutput("Selected project: "+self._projectName)
        data={"action":"UPDATE", "user":self._user, "projectname":self._projectName}
        if not self.sendMessage(json.dumps(data)):
            self.writeText("Failed to update project")
        self._websocket.request(1)

    def createProject(self, var2):
        data = {"action":"CREATE", "projectname":self._newProject.getText()}
        if not self.sendMessage(json.dumps(data)):
            self.writeText("Failed to create project")
        self._projectName = self._newProject
        self._websocket.request(1)

    def deleteProject(self, var2):
        data = {"action":"DELETE", "projectname":self._projectList.getSelectedValue()} # fyi: will not actually delete any requests from the db, but the project is deleted and will not be visible in burp
        if not self.sendMessage(json.dumps(data)):
            self.writeText("Failed to delete project")
        self._websocket.request(1)



    ##### WEBSOCKET PART ######

    ###### UI ######
    def getTabCaption(self):
        return "Highlight-Sharing"
    def toggleScheme(self,var2):
        self._scheme = not self._scheme
    def toggleDomain(self,var2):
        self._domain = not self._domain
    def togglePath(self,var2):
        self._path = not self._path
    def toggleQuery(self,var2):
        self._query = not self._query

    def getUiComponent(self):
        panel=JPanel()

        scheme = JCheckBox("Scheme", actionPerformed= self.toggleScheme)
        scheme.setSelected(True)
        panel.add(scheme)
        domain = JCheckBox("Domain", actionPerformed= self.toggleDomain)
        domain.setSelected(True)
        panel.add(domain)
        path = JCheckBox("Path", actionPerformed= self.togglePath)
        path.setSelected(True)
        panel.add(path)
        query = JCheckBox("Query", actionPerformed= self.toggleQuery)
        panel.add(query)
        self._wsStringButton = JTextField('', 40)
        label = JLabel('WS String:', SwingConstants.RIGHT)
        panel.add(label)
        panel.add(self._wsStringButton)

        self._userButton = JTextField('', 10)
        label = JLabel('Username',SwingConstants.RIGHT)
        panel.add(label)
        panel.add(self._userButton)

        panel.add(JLabel("Project name:", SwingConstants.RIGHT))
        self._projectList = JList(self._projectNames)
        panel.add(self._projectList)

        projectButton = JButton("Select Project", actionPerformed=self.selectProject)
        panel.add(projectButton)

        deleteButton = JButton("Delete Project", actionPerformed=self.deleteProject)
        panel.add(deleteButton)


        self._newProject = JTextField('', 15)
        label = JLabel('New project',SwingConstants.RIGHT)
        panel.add(label)
        panel.add(self._newProject)

        button=JButton("Create project", actionPerformed=self.createProject)
        panel.add(button)

        button=JButton("Connect", actionPerformed=self.connectWebsocket)
        panel.add(button)

        self._messageBox = JLabel("")
        panel.add(self._messageBox)

        return panel
    ###### UI ######



    def registerExtenderCallbacks(self,callbacks):
        self._callbacks=callbacks
        self._callbacks.printOutput("Highlight-Sharing "+ self.version)
        self._helpers=callbacks.getHelpers()
        self._callbacks.setExtensionName("Highlight-Sharing")
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerExtensionStateListener(self)
        self._connected=False
        self._requestIds=[]
        return

    def extensionUnloaded(self): # Will close the db connection when extension is unloaded
        self.writeText("Not Connected")
        if self._websocket:
            self._websocket.sendClose(1000, "Just closin")


    def createMenuItems(self, invocation): # to be removed :)
        ctx = invocation.getInvocationContext()
        ## Only works in http history and site map
        if ctx != invocation.CONTEXT_TARGET_SITE_MAP_TABLE and ctx != invocation.CONTEXT_TARGET_SITE_MAP_TREE and ctx != invocation.CONTEXT_PROXY_HISTORY:
            return None
        for i in invocation.getSelectedMessages(): ## hacky hacky workaround... need to right click after all are highlighted
            color = i.getHighlight()
            if color:
                url = i.getUrl().toString()
                type = ""
                value = ""
                if self._scheme:
                    type+="1"
                    value+=url.split(":")[0]+"://"
                else:
                    value+="dummy://"
                    type+="0"
                if self._domain:
                    value+=url.split("/")[2]
                    type+="1"
                else:
                    value+="dummy"
                    type+="0"
                if self._path:
                    value+="/"+"/".join(url.split("?")[0].split("/")[3:])
                    type+="1"
                else:
                    value+="/"
                    type+="0"
                if self._query:
                    value+="?"+"?".join(url.split("?")[1:])
                    type+="1"
                else:
                    value+="?"
                    type+="0"
                comment=i.getComment()
                data = {"user":self._user, "type":type, "value":value, "color":color, "comment":comment, "projectname":self._projectName}
                self.sendMessage(json.dumps(data))
        return None

    def updateReq(self, type, value, color, comment):
        if self.debugging:
            self._callbacks.printOutput("Updating requests")
        reqs = self._callbacks.getSiteMap("")
        scheme = ""
        domain=""
        path = ""
        query = ""
        if type[0] == "1":
            scheme = value.split(":")[0] # need to verify that these values are correct
        if type[1] == "1":
            domain = value.split("/")[2]
        if type[2] == "1":
            path = "/"+"/".join(value.split("?")[0].split("/")[3:])
        if type[3] == "1":
            query = "?"+"?".join(value.split("?")[1:])

        for i in reqs:
            scheme2 = ""
            domain2 = ""
            path2 = ""
            query2 = ""
            url = i.getUrl().toString()
            if scheme != "":
                scheme2 = url.split(":")[0]
            if domain != "":
                domain2 = url.split("/")[2]
            if path != "":
                path2 = "/"+"/".join(url.split("?")[0].split("/")[3:]) 
            if query != "":
                query2 = "?"+"?".join(url.split("?")[1:])
            url = i.getUrl().toString().split("?")[0]
            if scheme != scheme2 or domain != domain2 or path != path2 or query != query2:
                continue
            if self.debugging:
                self._callbacks.printOutput("Setting color of " + url)
            i.setHighlight(color)
            if comment != "":
                if self.debugging:
                    self._callbacks.printOutput("Setting comment of "+url)
                i.setComment(comment)
        if self.debugging:
            self._callbacks.printOutput("Updating requests done")
