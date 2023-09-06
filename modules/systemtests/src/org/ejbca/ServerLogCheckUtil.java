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
package org.ejbca;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.LogRedactionUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class ServerLogCheckUtil {

    private static final Logger log = Logger.getLogger(ServerLogCheckUtil.class);
    private static final String[] LOG_LEVELS = {"INFO", "DEBUG", "ERROR", "TRACE", "WARN", "FATAL"};
    
    // case insensitive: do not use 'CA' here as too short
    private static final String[] IGNORED_ON_LOWERCASE_PREFIXES = 
                        {"issuerdn", "issuer", "cadn", "admin", "administrator"};
    // "admin ::: CN=blah" -> 'CN' starts at index 10, 'admin' ends at index 4, slack needed 6
    private static final int PREFIXES_SLACK = 10;
    
    private static Pattern SUBJECT_DN_COMPONENTS;
    public static List<String> whiteListedPackages;
    public static List<String> whiteListedClasses;
    // class -> method, beware of whitelisting methods with same name
    // we might need lineNo with some slack in config later
    public static Map<String, List<String>> whiteListedMethods;
    
    // may have multiple entries for same class but only one with both class+method
    public static Map<String, List<String>> whiteListedConditionalMethods;
    
    static {
        loadConfigs();
    }
    
    private static void loadConfigs() {
        whiteListedPackages = new ArrayList<>();
        whiteListedClasses = new ArrayList<>();
        whiteListedMethods = new HashMap<>();
        whiteListedConditionalMethods =  new HashMap<>();
        
        new ServerLogCheckUtil().loadWhiteListPiiConfiguration();
        
        SUBJECT_DN_COMPONENTS = Pattern.compile(LogRedactionUtils.getSubjectDnRedactionPattern(), Pattern.CASE_INSENSITIVE);
    }
        
    public static class ServerLogRecord {
        
        private String level;
        private String className;
        private String methodName;
        private String lineNo;
        private String message;
        
        private Boolean isWhiteListed;
        
        public ServerLogRecord(String level, String className, String methodName, String lineNo, String message) {
            this.className = className;
            this.methodName = methodName;
            this.lineNo = lineNo;
            this.message = message;
            this.level = level;
        }

        @Override
        public String toString() {
            return "ServerLogRecord [level=" + level + ", className=" + className + ", methodName=" + methodName + ", lineNo=" + lineNo + ", message="
                    + message + "]";
        }

        public String getLevel() {
            return level;
        }

        public String getClassName() {
            return className;
        }

        public String getMethodName() {
            return methodName;
        }

        public String getLineNo() {
            return lineNo;
        }

        public String getMessage() {
            return message;
        }

        public Boolean isWhiteListed(Set<String> issuerDns, Set<String> adminDns) {
            
            if (isWhiteListed!=null) {
                return isWhiteListed;
            }
            String packageName = className.substring(0, className.lastIndexOf("."));
            String classSimpleName = className.substring(className.lastIndexOf(".")+1);
            List<String> methods = whiteListedMethods.getOrDefault(classSimpleName, whiteListedMethods.get(className));

            if (whiteListedPackages.contains(packageName) || 
                    whiteListedClasses.contains(classSimpleName) ||
                    whiteListedClasses.contains(className) || 
                    (methods!=null && methods.contains(methodName) )) {
                isWhiteListed = true;
                return isWhiteListed;
            }
            
            // check if says issuerDn with lower
            Matcher m = SUBJECT_DN_COMPONENTS.matcher(message);
            if(m.find()) { // always true if Wildfly filter is enabled
                int foundOn = m.start();
                String wholePrefix = message.substring(0, foundOn).trim().toLowerCase();
                for (String p: IGNORED_ON_LOWERCASE_PREFIXES) {
                    int detected = wholePrefix.lastIndexOf(p);
                    if (detected > 0 && 
                            (detected + p.length() + PREFIXES_SLACK > wholePrefix.length()) ) {
                        isWhiteListed = true;
                        return isWhiteListed;
                    }
                }
                
                if (whiteListedConditionalMethods.containsKey(classSimpleName + ":" +  methodName)) {
                    for (String p: whiteListedConditionalMethods.get(classSimpleName + ":" +  methodName)) {
                        int detected = wholePrefix.lastIndexOf(p);
                        if (detected > 0 && 
                                (detected + p.length() + PREFIXES_SLACK > wholePrefix.length()) ) {
                            isWhiteListed = true;
                            return isWhiteListed;
                        }
                    }
                }                
            }
            
            // a bit expensive but we only create in average 3 CAs for each class and
            for (String s: issuerDns) {
                message = message.replace(s, "");
            }
            
            for (String s: adminDns) {
                message = message.replace(s, "");
            }
            
            m = SUBJECT_DN_COMPONENTS.matcher(message);
            if(!m.find()) { // false positives should be gone now
                isWhiteListed = true;
                return isWhiteListed;
            }
            
            log.error("Not whitelisted: " + toString());
            isWhiteListed = false;
            return isWhiteListed;
        }
                        
    }
    
    public static ServerLogRecord parseServerLogRecord(String loggedLine) {
        try {
            return unwrappedParseServerLogRecord(loggedLine);
        } catch (Exception e) {
            // may be a exception stacktrace or external log
            log.error("Failed parsing, " + loggedLine); 
            return null;
        }
    }
    
    private static ServerLogRecord unwrappedParseServerLogRecord(String loggedLine) {
        
        if (StringUtils.isEmpty(loggedLine) || loggedLine.length() < 15 
                || loggedLine.contains("org.jboss")
                || loggedLine.contains("org.wildfly")
                || loggedLine.contains("org.xnio")) {
            return null;
        }
        
        int levelStart = 51;
        int classNameStart, methodNameStart, lineNoStart;
        int classNameEnd, methodNameEnd, lineNoEnd;
        
        String level=null, className, methodName, lineNo;
        for(String l: LOG_LEVELS) {
            int i = loggedLine.substring(0, 50).indexOf(l);
            if (i > 0 && levelStart > i) {
                level = l;
                levelStart = i;
            }
        }
        
        if (level==null) {
            return null;
        }
        
        classNameStart = loggedLine.indexOf("[", levelStart+1)+1;
        methodNameStart = loggedLine.indexOf("[", classNameStart+1)+1;
        lineNoStart = loggedLine.indexOf("[", methodNameStart+1)+1;

        classNameEnd = loggedLine.indexOf("]", classNameStart+1);
        methodNameEnd = loggedLine.indexOf("]", methodNameStart+1);
        lineNoEnd = loggedLine.indexOf("]", lineNoStart+1);

        className = loggedLine.substring(classNameStart, classNameEnd);
        methodName = loggedLine.substring(methodNameStart, methodNameEnd);
        lineNo = loggedLine.substring(lineNoStart, lineNoEnd);
        
        return new ServerLogRecord(level, className, methodName, lineNo, loggedLine.substring(lineNoEnd+1));
    }
    
    
    protected void loadWhiteListPiiConfiguration() {
        String config = null;
        try {
            config = Files.readString(Paths.get(getClass().getClassLoader().getResource("white_listed_pii_logging_config.json").toURI()));
        } catch (Exception e) {
            // skip
        }
        
        loadWhiteListPiiConfiguration(config);
    }
    
    protected void loadWhiteListPiiConfiguration(String config) {
        
        if (config==null) {
            log.error("Could not load white list config for PII log test");
            return;
        }
        
        try {
            JSONObject configJson = (JSONObject) new JSONParser().parse(config);
            JSONArray readWhiteListedPackages = (JSONArray)configJson.get("packages");
            readWhiteListedPackages.forEach(x -> whiteListedPackages.add((String) x));
            JSONArray readWhiteListedClasses = (JSONArray)configJson.get("classes");
            readWhiteListedClasses.forEach(x -> whiteListedClasses.add((String) x));
            JSONArray readWhiteListedMethods = (JSONArray)configJson.get("methods");

            for(int i=0; i<readWhiteListedMethods.size(); i++) {
                JSONArray readIgnoredMethods = (JSONArray)((JSONObject)readWhiteListedMethods.get(i)).get("ignoredMethods");
                List<String> methods = new ArrayList<>();
                readIgnoredMethods.forEach(x -> methods.add((String) x));
                
                JSONArray readPrefixes = (JSONArray)((JSONObject)readWhiteListedMethods.get(i)).get("prefixes");
                if (readPrefixes!=null) {
                    List<String> prefixes = new ArrayList<>();
                    readPrefixes.forEach(x -> prefixes.add((String) x));
                    String className = (String)((JSONObject)readWhiteListedMethods.get(i)).get("class");
                    for (String m : methods) {
                        whiteListedConditionalMethods.put(className+":"+m, prefixes);
                    }
                } else {
                    whiteListedMethods.put(
                        (String)((JSONObject)readWhiteListedMethods.get(i)).get("class"), 
                        methods);
                }
            }

        } catch (Exception e) {
            log.error("Could not parse JSON white list config for PII log test");
        }
        
    }
}
