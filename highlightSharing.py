from burp import IBurpExtender, ITab
import time
from burp import IContextMenuFactory, IBurpExtenderCallbacks, IRequestInfo,IExtensionStateListener
from javax.swing import JPanel, JLabel, JTextField, SwingConstants, JButton
from com.ziclix.python.sql import zxJDBC
from java.net.http import HttpClient;
from java.net.http import WebSocket
from java.net import URI;
import java.lang.CharSequence
import json


class BurpExtender(IBurpExtender,IContextMenuFactory,ITab, IRequestInfo, IBurpExtenderCallbacks,IExtensionStateListener, WebSocket.Listener):

    def __init__(self):
        self.debugging=False
        self.version="v1.0"

    ##### WEBSOCKET PART ######

    def onOpen(self, websocket):
        self._websocket=websocket
        data={"action":"UPDATE", "user":self._user, "project":self._projectName}
        if not self.sendMessage(json.dumps(data)):
            self.writeText("Not connected: Failed to connect to the websocket server")
        self._websocket.request(1)
        self.writeText("Connected")
        self._callbacks.printOutput("Connected to Burp-Highlight-Sharing "+ self.version)

    def onClose(self, websocket, statusCode, reason):
        self.writeText("Not connected: connection closed")

    def onText(self, websocket, data, last):
        if self.debugging:
            self._callbacks.printOutput("Received message")
        self._websocket=websocket
        content = json.loads(data.toString())
        user = content["user"]
        project = content["project"]
        if user != self._user and project == self._projectName:
            if self.debugging:
                self._callbacks.printOutput("Updating path "+content["path"])
            self.updateReq(content["path"], content["color"], content["comment"])
        elif self.debugging:
            self._callbacks.printOutput("NOT UPDATING "+content["path"])
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
        self.writeText("Not connected")
        self._wsString = self._wsStringButton.getText()
        self._projectName = self._projectButton.getText()
        self._user = self._userButton.getText()
        if self._projectName =="" or self._user == "":
            self.writeText("Not connected: Please specify a username and ws string")
            return
        client = HttpClient.newHttpClient()
        client.newWebSocketBuilder().buildAsync(URI.create(self._wsString),  self);

    def toggleDebug(self, event):
        self.debugging = not self.debugging
        if self.debugging:
            self._messageBox.text+=" and debugging enabled"

    def writeText(self, connection):
        if self.debugging:
            self._messageBox.text=connection+" and debugging enabled"
        else:
            self._messageBox.text=connection



    ##### WEBSOCKET PART ######

    ###### UI ######
    def getTabCaption(self):
        return "Highlight-Sharing"

    def getUiComponent(self):
        panel=JPanel()

        self._wsStringButton = JTextField('', 40)
        label = JLabel('WS String:', SwingConstants.RIGHT)
        panel.add(label)
        panel.add(self._wsStringButton)

        self._userButton = JTextField('', 10)
        label = JLabel('Username',SwingConstants.RIGHT)
        panel.add(label)
        panel.add(self._userButton)

        self._projectButton = JTextField('', 15)
        panel.add(JLabel("Project name:", SwingConstants.RIGHT))
        panel.add(self._projectButton)


        button=JButton("Connect", actionPerformed=self.connectWebsocket)
        panel.add(button)

        self._messageBox = JLabel("")
        panel.add(self._messageBox)


        debug = JButton("Debug", actionPerformed=self.toggleDebug)
        panel.add(debug)

        return panel
    ###### UI ######



    def registerExtenderCallbacks(self,callbacks):
        self._callbacks=callbacks
        self._helpers=callbacks.getHelpers()
        self._callbacks.setExtensionName("Highlight-Sharing")
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerExtensionStateListener(self)
        self._enabled=True
        self._connected=False
        self._requestIds=[]
        return

    def extensionUnloaded(self): # Will close the db connection when extension is unloaded
        self.writeText("Not Connected")
        if self._websocket:
            self._websocket.sendClose(1000, "Just closin")


    def createMenuItems(self, invocation):
        ctx = invocation.getInvocationContext()
        ## Only works in http history and site map
        if ctx != invocation.CONTEXT_TARGET_SITE_MAP_TABLE and ctx != invocation.CONTEXT_TARGET_SITE_MAP_TREE and ctx != invocation.CONTEXT_PROXY_HISTORY:
            return None
        for i in invocation.getSelectedMessages(): ## hacky hacky workaround... need to right click after all are highlighted
            color = i.getHighlight()
            if color:
                comment=i.getComment()
                path=i.getUrl().toString().split("?")[0]
                data = {"user":self._user, "path":path, "color":color, "comment":comment, "project":self._projectName}
                self.sendMessage(json.dumps(data))
        return None

    def updateReq(self, path, color, comment):
        if self.debugging:
            self._callbacks.printOutput("Updating requests")
        reqs = self._callbacks.getSiteMap("")
        for i in reqs:
            url = i.getUrl().toString().split("?")[0]
            if path == url:
                i.setHighlight(color)
                if self.debugging:
                    self._callbacks.printOutput("Setting color of " + path)
                if comment != "":
                    if self.debugging:
                        self._callbacks.printOutput("Setting comment of "+path)
                    i.setComment(comment)
        if self.debugging:
            self._callbacks.printOutput("Updating requests done")
