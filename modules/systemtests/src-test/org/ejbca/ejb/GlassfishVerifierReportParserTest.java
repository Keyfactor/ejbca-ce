/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ejb;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Glassfish 2.1.1 comes with an JEE5 verifier. This JUnit test will analyze the output report
 * and provide a format of the result that we can use for continuous integration testing.
 * 
 * Example of argument to be supplied to the JVM
 *  -Dvertest.report=/path/ejbca.ear.xml
 *  -Dvertest.expectedErrors=1
 *  -Dvertest.expectedFailures=14
 *  -Dvertest.expectedWarnings=8
 * 
 * @version $Id$
 */
public class GlassfishVerifierReportParserTest {

	private static final Logger log = Logger.getLogger(GlassfishVerifierReportParserTest.class);
	
	private String verifierReport;
	private int expectedErrors = 0;
	private int expectedFailures = 0;
	private int expectedWarnings = 0;
	
	@Before
    public void setUp() throws Exception {
    	verifierReport = System.getProperty("vertest.report");
    	log.info("vertest.report="+verifierReport);
		assertTrue("vertest.report invalid or not set.", new File(verifierReport).exists());
		expectedErrors = Integer.parseInt(System.getProperty("vertest.expectedErrors", "0"));
		expectedWarnings = Integer.parseInt(System.getProperty("vertest.expectedWarnings", "0"));
		expectedFailures = Integer.parseInt(System.getProperty("vertest.expectedFailures", "0"));
    }
    
	@After
    public void tearDown() {
    }
    
    @Test
    public void testJavaEnterpriseEditionCompliance() throws ParserConfigurationException, SAXException, IOException {
        javax.xml.parsers.DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.parse(new File(verifierReport));
        doc.getDocumentElement().normalize();
        Element root = doc.getDocumentElement();
        log.info("Root element " + root.getNodeName());
        NodeList tests = root.getElementsByTagName("test");
        int warnCount = 0;
        int failCount = 0;
		// Quick and dirty XML parsing
        for (int i=0; i<tests.getLength(); i++) {
    		NodeList childNodes = tests.item(i).getChildNodes();
    		String testName = childNodes.item(1).getTextContent();
    		String testAssertion = childNodes.item(3).getTextContent();
    		String testDescription = childNodes.item(5).getTextContent();
    		String parentNodeName = tests.item(i).getParentNode().getNodeName();
    		if ("warning".equals(parentNodeName)) {
        		warnCount++;
        		log.warn(testName + ": " + testAssertion + "\n " + testDescription);
    		} else if ("failed".equals(parentNodeName)) {
        		failCount++;
        		log.error(testName + ": " + testAssertion + "\n " + testDescription);
    		} else {
        		log.info(testName + ": " + testAssertion + "\n " + testDescription);
    		}
        }
        NodeList errors = root.getElementsByTagName("error");
        int errorCount = errors.getLength();
        for (int i=0; i<errors.getLength(); i++) {
    		NodeList childNodes = errors.item(i).getChildNodes();
        	log.error(childNodes.item(1).getTextContent() + ": " + childNodes.item(3).getTextContent());
        }
        assertEquals("JEE5 complicance tests returned with more or less ERRORs than expected. See log output for more details. Adjust this assertion if the number is lower.", expectedErrors, errorCount);
        assertEquals("JEE5 complicance tests returned with more or less FAILUREs than expected. See log output for more details. Adjust this assertion if the number is lower.", expectedFailures, failCount);
        assertEquals("JEE5 complicance tests returned with more or less WARNINGs than expected. See log output for more details. Adjust this assertion if the number is lower.", expectedWarnings, warnCount);
    }
}
