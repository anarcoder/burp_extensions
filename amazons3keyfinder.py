import re
import os
import array
import inspect
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


ISSUE = "AWS Key Finder"
SEVERITY = "High"
ISSUE_DETAIL = "AWS Key found, <b>{0}</b>"
CONFIDENCE = "Certain"
PUBLISH_ISSUE = "CustomScanIssue(currentMessage.getHttpService(),"\
                "self._helpers.analyzeRequest(currentMessage)"\
                ".getUrl(),[self._callbacks.applyMarkers"\
                "(currentMessage, None, markers)]"\
                ",\"{0}\",\"{1}\",\"{2}\",\"{3}\")"

AWS_XML = [r'ListBucketResult']

AWS_XML_RGX = [re.compile(error, re.IGNORECASE) for error in AWS_XML]


class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck,
                   IContextMenuFactory, IParameter):

    def banner(self):
        print "Successfully loaded AWS Key Finder - v0.1"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("AWS Key Finder")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)
        self.banner()

    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to AWS Key Finder",
                                actionPerformed=self.findKey))
        return menu_list

    def findKey(self, event):
        httpRequestResponse = self.context.getSelectedMessages()
        with open('/tmp/teste.xml', 'a+') as f:
            target = ''
            for currentRequest in httpRequestResponse:
                #print self._helpers.analyzeRequest(currentRequest.getRequest()).getUrl()

                #raw_response = self._helpers.bytesToString(currentRequest.getResponse())[self._helpers.analyzeResponse(currentRequest.getResponse()).getBodyOffset():]
                #f.write(raw_response)
            #os.system('grep -Pi "<Key>.*?<\/Key>" /tmp/teste.xml -o |sed "s/<Key>//g" |sed "s/<\/Key>//g" | grep -Piv "png|jpg" > /tmp/teste2.xml')
            #data = ['http://vatomanocu/{0}'.format(line.strip()) for line in open("/tmp/teste2.xml", 'r')]
            #print data
            




    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        if messageIsRequest == 0 and toolFlag == 8:
            response = self._helpers.analyzeResponse(
                currentMessage.getResponse())
            if response.getStatusCode() == 404:
                return
            self.validate_if_erros_displayed(
                currentMessage, inspect.stack()[0][3])

    def doPassiveScan(self, currentMessage):
        response = self._helpers.analyzeResponse(currentMessage.getResponse())
        if response.getStatusCode() == 404:
            return
        return self.validate_if_erros_displayed(
            currentMessage, inspect.stack()[0][3])

    def validate_if_erros_displayed(self, currentMessage, whoCallMe=None):
        raw_response = self._helpers.bytesToString(
            currentMessage.getResponse())
        for error in AWS_XML_RGX:
            match = error.search(raw_response)
            if match:
                match_res = match.group(0)
                start_pos = raw_response.find(match_res)
                markers = [array.array('i', [start_pos, start_pos + len(match_res)])]
                issue = PUBLISH_ISSUE.format(ISSUE,
                                             ISSUE_DETAIL.format(match_res),
                                             CONFIDENCE, SEVERITY)
                if whoCallMe == 'doPassiveScan':
                    return [eval(issue)]
                self._callbacks.addScanIssue(eval(issue))

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueName() == newIssue.getIssueName()):
            return -1
        else:
            return 0


class CustomScanIssue(IScanIssue):

    def __init__(self, httpService, url, httpMessages,
                 name, detail, confidence, severity):
        self._http_service = httpService
        self._url = url
        self._http_messages = httpMessages
        self._name = name
        self._detail = detail + '<br/><br/><div style="font-size:8px">'\
                                'This issue was reported by '\
                                'AWS Key Finder</div>'
        self._severity = severity
        self._confidence = confidence
        return

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service
