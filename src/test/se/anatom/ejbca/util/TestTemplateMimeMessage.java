package se.anatom.ejbca.util;

import java.util.HashMap;

import junit.framework.TestCase;

import org.ejbca.util.TemplateMimeMessage;

/**
 * TestCase for TemplateMimeMessage
 */
public class TestTemplateMimeMessage extends TestCase {

    private TemplateMimeMessage message;

    protected void setUp() throws Exception {
        HashMap patterns = new HashMap();
        patterns.put("username", "John Doe");
        patterns.put("password", "secret");
        message = new TemplateMimeMessage(patterns, null);
    }

    public void testContent() throws Exception {
        String input = "Hello ${username}, your password is ${password}";
        String expected ="Hello John Doe, your password is secret";
        message.setContent(input, "text/plain");
        String output = (String)message.getContent();
        assertEquals(expected, output);
    }

    public void testContentPatternCase() throws Exception {
        String input = "Hello ${uSeRnAmE}, your password is ${pAsSwOrD}";
        String expected = input;
        message.setContent(input, "text/plain");
        String output = (String)message.getContent();
        assertEquals(expected, output);
    }

    public void testMixedPatterns() throws Exception {
        String input = "Hello ${username}, your password is ${pAsSwOrD}";
        String expected = "Hello John Doe, your password is ${pAsSwOrD}";
        message.setContent(input, "text/plain");
        String output = (String)message.getContent();
        assertEquals(expected, output);
    }
    
}
