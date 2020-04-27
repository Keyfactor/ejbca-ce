package org.ejbca.ui.cli.clientToolBoxTest.tests;

import java.net.URL;

import javax.xml.namespace.QName;

import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;

class FixWithWS  extends CommandLine {
	private static EjbcaWS ws;
	protected static EjbcaWS getWS() throws Exception {
		if (ws!=null) {
			return ws;
		}
		getClientToolBoxMainMethod().invoke(null, (Object)new String[]{"EjbcaWsRaCli", "finduser", "USERNAME", "EQUALS", "superadmin"});
		final URL webServiceURL = new URL("https://"+"ca"+":8443/ejbca/ejbcaws/ejbcaws?wsdl");
		final QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
		ws = new EjbcaWSService(webServiceURL,qname).getEjbcaWSPort();
		return ws;
	}
}
