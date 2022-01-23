from burp import IBurpExtender, ITab
from burp import IHttpListener
from burp import IProxyListener
from burp import IContextMenuFactory, IBurpExtenderCallbacks, IRequestInfo,IExtensionStateListener
from javax.swing import JMenuItem,JPanel, JLabel, JComboBox, JTextField, SwingConstants, JButton
from java.awt.event import ActionListener
from java.io import PrintWriter
from com.ziclix.python.sql import zxJDBC

class BurpExtender(IBurpExtender,IContextMenuFactory,ActionListener,ITab, IRequestInfo, IBurpExtenderCallbacks, IExtensionStateListener):

    def getTabCaption(self):
        return "Highlight-Sharing"

    def getUiComponent(self):
        panel=JPanel()

        self._dbStringButton = JTextField('', 40)
        label = JLabel('DbString:', SwingConstants.RIGHT)
        panel.add(label)
        panel.add(self._dbStringButton)

        self._projectButton = JTextField('', 15)
        panel.add(JLabel("Project name:", SwingConstants.RIGHT))
        panel.add(self._projectButton)


        button=JButton("Connect", actionPerformed=self.connectDb)
        panel.add(button)

        self._messageBox = JLabel("")
        panel.add(self._messageBox)
        return panel


    def connectDb(self, event):
        self._messageBox.text = "Not connected to db"
        dbString=self._dbStringButton.getText()
        self._projectName = self._projectButton.getText()
        if self._projectName == "":
            self._messageBox.text = "Not connected to db: please set a project name"
            return
        self._conn = zxJDBC.connect("jdbc:"+dbString, None, None, "com.mysql.jdbc.Driver")
        self._connected=True
        self._cursor = self._conn.cursor()
        self._cursor.execute("CREATE TABLE IF NOT EXISTS request (id int not null auto_increment, projectName varchar(255) not null, path varchar(255), color varchar(10),comment varchar(255),primary key(id), CONSTRAINT unique_key UNIQUE(path,projectName));")
        self._messageBox.text="Connected to db"


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
        self._cursor.close()
        self._conn.close()


    def createMenuItems(self, invocation):
        ctx = invocation.getInvocationContext()
        ## Only works in http history and site map
        if ctx != invocation.CONTEXT_TARGET_SITE_MAP_TABLE and ctx != invocation.CONTEXT_TARGET_SITE_MAP_TREE and ctx != invocation.CONTEXT_PROXY_HISTORY:
            return None
        for i in invocation.getSelectedMessages(): ## hacky hacky workaround... need to right click after all are highlighted
            color = i.getHighlight()
            if color and self._connected:
                if not self._cursor:
                    self._cursor = self._conn.cursor()
                comment=i.getComment()
                query = "INSERT into request (projectName, path, color) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE projectName=(?), path=(?), color=(?);"
                path=i.getUrl().toString().split("?")[0]
                self._cursor.executemany(query, [self._projectName, path, color,self._projectName,path,color])
                if comment != "":
                    query = "INSERT INTO request (projectName, path, comment) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE projectName=(?), path=(?), comment=(?);"
                    self._cursor.executemany(query, [self._projectName, path, comment, self._projectName, path, comment])
                self._requestIds.append(self._cursor.lastrowid)
        if self._connected:
            self._conn.commit()
            self.updateReqs()
        return None

    def updateReqs(self):
        query = "select path, color, comment from request where projectName = (?);"
        self._cursor.executemany(query, [self._projectName])
        requests=self._cursor.fetchall()
        reqs = self._callbacks.getSiteMap("")
        for i in reqs:
            url = i.getUrl().toString().split("?")[0]
            for j in requests:
                url2 = j[0]
                if url == url2:
                    i.setHighlight(j[1])
                    i.setComment(j[2])


