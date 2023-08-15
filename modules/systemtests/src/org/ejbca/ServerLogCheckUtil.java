package org.ejbca;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

//import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class ServerLogCheckUtil {

    private static final Logger log = Logger.getLogger(ServerLogCheckUtil.class);
    private static final String[] LOG_LEVELS = {"INFO", "DEBUG", "ERROR", "TRACE", "WARN", "FATAL"};
    
    public static List<String> whiteListedPackages;
    public static List<String> whiteListedClasses;
    // class -> method, beware of methods with same name
    public static Map<String, List<String>> whiteListedMethods;
    
    static {
        loadConfigs();
    }
    
    private static void loadConfigs() {
        whiteListedPackages = new ArrayList<>();
        whiteListedClasses = new ArrayList<>();
        whiteListedMethods = new HashMap<>();
        
        new ServerLogCheckUtil().loadWhiteListPiiConfiguration();
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

        public Boolean isWhiteListed() {
            
            if (isWhiteListed==null) {
                String packageName = className.substring(0, className.lastIndexOf("."));
                String classSimpleName = className.substring(className.lastIndexOf("."));
                List<String> methods = whiteListedMethods.getOrDefault(classSimpleName, whiteListedMethods.get(className));

                if (whiteListedPackages.contains(packageName) || 
                        whiteListedClasses.contains(classSimpleName) ||
                        whiteListedClasses.contains(className) || 
                        (methods!=null && methods.contains(methodName) )) {
                    isWhiteListed = true;
                } else {
                    isWhiteListed = false;
                }

            }
            
            return isWhiteListed;
        }
                        
    }
    
    public static ServerLogRecord parseServerLogRecord(String loggedLine) {
        
        if (StringUtils.isEmpty(loggedLine) || loggedLine.length() < 15 
                || loggedLine.contains("org.jboss")
                || loggedLine.contains("org.wildfly")) {
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
    
    public void loadWhiteListPiiConfiguration() {
        
        String config = null;
        try {
            config = Files.readString(Paths.get(getClass().getClassLoader().getResource("white_listed_pii_logging_config.json").toURI()));
        } catch (Exception e) {
            // skip
        }
        
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
                whiteListedMethods.put(
                        (String)((JSONObject)readWhiteListedMethods.get(i)).get("class"), 
                        methods);
            }

        } catch (Exception e) {
            log.error("Could not parse JSON white list config for PII log test");
        }
        
    }
}
