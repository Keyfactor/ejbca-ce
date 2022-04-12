package org.ejbca.webtest.helper;


import java.util.List;
import org.apache.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;


public class MailHelper extends BaseHelper { 
        
    private static final Logger log = Logger.getLogger(MailHelper.class);
    
    public MailHelper(final WebDriver webDriver) {
        super(webDriver);
    }
    
    public static class Page {
        static final String MAIL_URL = "http://192.168.33.113/cgi-bin/mail.sh";  
        static final By HEADER_SUBJECT_VALUE = By.className("header_subject_value");
        
    }   
        
    public void openPage() {
            webDriver.get(Page.MAIL_URL);
    }    
      
    public String getEmailLastSubject() {        
        List<WebElement> subjects = findElements(Page.HEADER_SUBJECT_VALUE);        
        int size = subjects.size();
        String lastSubject = subjects.get(size-1).getText();
        log.info("Found subject: \"" + lastSubject + "\"");
        
        return lastSubject;        
    }      
 }
