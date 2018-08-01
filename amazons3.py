import re
import array
import inspect
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IHttpListener


ISSUE = "Amazon S3 References"
SEVERITY = "High"
ISSUE_DETAIL = "AWS reference found, <b>{0}</b>"
CONFIDENCE = "Certain"
PUBLISH_ISSUE = "CustomScanIssue(currentMessage.getHttpService(),"\
                "self._helpers.analyzeRequest(currentMessage)"\
                ".getUrl(),[self._callbacks.applyMarkers"\
                "(currentMessage, None, markers)]"\
                ",\"{0}\",\"{1}\",\"{2}\",\"{3}\")"

SUSP_STR = [r'.amazonaws\.com',
            r'-sa-east-1',
            r'amazonaws\.com',
            r'awsAccessKeyId',
            r'AccessKey',
            r'SecretKey']

SUSP_RGX = [re.compile(error, re.IGNORECASE) for error in SUSP_STR]


class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck):

    def banner(self):
        print "Successfully loaded AWS Ref Extension - v0.1"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("AWS Ref Extension")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        self.banner()

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
        for error in SUSP_RGX:
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
                                'AWS Ref Extension</div>'
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
