var oArgs = WScript.Arguments;

if (oArgs.length < 2) {
    WScript.Echo("usage: cscript xslt.js xml xsl");
    WScript.Quit();
}

xslFile = oArgs(0);
xmlFile = oArgs(1);

var xml = new ActiveXObject("MSXML2.DOMDocument.5.0");
var xsl = new ActiveXObject("MSXML2.FreeThreadedDOMDocument.5.0");
var xslTemplate = new ActiveXObject("MSXML2.XSLTemplate.5.0");

xml.validateOnParse = false;
xml.async = false;
xml.load(xmlFile);

if (xml.parseError.errorCode != 0)
    WScript.Echo("XML Parse Error: " + xml.parseError.reason);

xsl.async = false;
xsl.load(xslFile);

if (xsl.parseError.errorCode != 0)
    WScript.Echo("XSL Parse Error: " + xsl.parseError.reason);

xslTemplate.stylesheet = xsl;
var xslProcessor = xslTemplate.createProcessor();
xslProcessor.input = xml;

try {
    var writer = new ActiveXObject("MSXML2.MXXMLWriter.5.0");
    xslProcessor.output = writer;
    
    for (i=2; i<oArgs.length; i=i+2) {
        xslProcessor.addParameter(oArgs(i), oArgs(i+1));
    }
    
    xslProcessor.transform();
    WScript.Echo(writer.output);
}
catch(err) {
    WScript.Echo("Transformation Error: " + err.number + "*" + err.description);
}
