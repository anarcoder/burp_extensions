import re
import array
import inspect
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IHttpListener


ISSUE = "Detailed Configuration Error"
SEVERITY = "High"
ISSUE_DETAIL = "Detailed error found, <b>{0}</b>"
CONFIDENCE = "Certain"
PUBLISH_ISSUE = "CustomScanIssue(currentMessage.getHttpService(),"\
                "self._helpers.analyzeRequest(currentMessage)"\
                ".getUrl(),[self._callbacks.applyMarkers"\
                "(currentMessage, None, markers)]"\
                ",\"{0}\",\"{1}\",\"{2}\",\"{3}\")"

ERRORS = [r'\[(ODBC SQL Server Driver|SQL Server)\]', r'mysql_fetch_assoc',
          r'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near',
          r'A syntax error has occurred', r'ADODB.Field error', r'ASP.NET is configured to show verbose error messages',
          r'ASP.NET_SessionId', r'Active Server Pages error', r'An illegal character has been found in the statement',
          r'An unexpected token "END-OF-STATEMENT" was found', r'CLI Driver', r'Can\'t connect to local', r'Custom Error Message',
          r'DB2 Driver', r'DB2 Error', r'DB2 ODBC', r'Died at', r'Disallowed Parent Path', r'Error Diagnostic Information',
          r'Error Message : Error loading required libraries.', r'Error Report', r'Error converting data type varchar to numeric',
          r'Incorrect syntax near',r'Invalid procedure call or argument', r'Invision Power Board Database Error', r'JDBC Driver', r'JDBC Error', r'JDBC MySQL',
          r'JDBC Oracle', r'JDBC SQL', r'Microsoft OLE DB Provider for ODBC Drivers', r'Microsoft VBScript compilation error',
          r'Microsoft VBScript error', r'MySQL Driver', r'MySQL Error', r'MySQL ODBC', r'ODBC DB2', r'ODBC Driver', r'ODBC Error',
          r'ODBC Microsoft Access', r'ODBC Oracle', r'ODBC SQL', r'ODBC SQL Server', r'OLE/DB provider returned message',
          r'ORA-0', r'ORA-1', r'Oracle DB2', r'Oracle Driver', r'Oracle Error', r'Oracle ODBC', r'PHP Error',
          r'PHP Parse error', r'PHP Warning', r'Parent Directory', r'Permission denied: \'GetObject\'',
          r'PostgreSQL query failed: ERROR: parser: parse error', r'SQL Server Driver\]\[SQL Server', r'SQL command not properly ended',
          r'SQLException', r'Supplied argument is not a valid PostgreSQL result', r'Syntax error in query expression', r'The error occurred in',
          r'The script whose uid is', r'Type mismatch', r'Unable to jump to row', r'Unclosed quotation mark before the character string',
          r'Unterminated string constant', r'Warning: Cannot modify header information - headers already sent',
          r'Warning: Supplied argument is not a valid File-Handle resource in', r'Warning: mysql_query()',
          r'Warning: pg_connect(): Unable to connect to PostgreSQL server: FATAL', r'You have an error in your SQL syntax near',
          r'data source=', r'detected an internal error \[IBM\]\[CLI Driver\]\[DB2/6000\]', r'include_path', r'invalid query',
          r'is not allowed to access', r'missing expression', r'mySQL error with query', r'mysql error', r'on MySQL result index',
          r'supplied argument is not a valid MySQL result resource', r'unexpected end of SQL command']

ERROR_RGX = [re.compile(error, re.IGNORECASE) for error in ERRORS]


class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck):

    def banner(self):
        print "Successfully loaded DCE Extension - v0.1"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("DCE Extension")
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
        for error in ERROR_RGX:
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
                                'DCE Extension</div>'
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
