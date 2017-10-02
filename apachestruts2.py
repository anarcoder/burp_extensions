from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IHttpListener


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


class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck):

    def banner(self):
        print "Successfully loaded Apache Struts2 RCE - v0.1"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Apache Struts2 RCE Checker")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        self.banner()

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
