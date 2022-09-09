/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.config;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.enterprise.concurrent.ManagedScheduledExecutorService;

import org.apache.commons.configuration2.CompositeConfiguration;
import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.SystemConfiguration;
import org.apache.commons.configuration2.builder.ConfigurationBuilderEvent;
import org.apache.commons.configuration2.builder.ConfigurationBuilderResultCreatedEvent;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.ReloadingFileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.event.EventListener;
import org.apache.commons.configuration2.convert.LegacyListDelimiterHandler;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.configuration2.reloading.ReloadingController;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.apache.log4j.Logger;

/**
 * This is a singleton. Used to configure common-configuration with our sources.
 *
 * Use like this: String value = ConfigurationHolder.getString("my.conf.property.key"); or String value =
 * ConfigurationHolder.getString("my.conf.property.key", "default value"); or String value =
 * ConfigurationHolder.getExpandedString("my.conf.property.key", "default value"); to be able to parse values containing ${property}
 *
 * See in-line comments below for the sources added to the configuration.
 *
 * @version $Id$
 */
public final class ConfigurationHolder {

    private static final Logger log = Logger.getLogger(ConfigurationHolder.class);

    private static volatile CompositeConfiguration defaultValues;

    private static volatile CompositeConfiguration config = null;
    private static CompositeConfiguration configBackup = null;

    /** cesecore.properties must be first in this file, because CONFIGALLOWEXTERNAL is defined in there.
     * NOTE: diff between EJBCA and CESeCore*/
    private static final String[] CONFIG_FILES = { "cesecore.properties", "extendedkeyusage.properties",
            "cache.properties", "database.properties", "databaseprotection.properties", "backup.properties", "va.properties", "ocsp.properties"};

    /** Configuration property that enables dynamic reading of properties from the file system. This is not allowed by default for security reasons. */
    private static final String CONFIGALLOWEXTERNAL = "allow.external-dynamic.configuration";

    private static final String DEFAULT_CONFIG_FILE = "/defaultvalues.properties";

    /** This is a singleton so it's not allowed to create an instance explicitly */
    private ConfigurationHolder() {
    }

    public static synchronized Configuration instance() {
        if (config == null) {
            // Read in default values
            defaultValues = new CompositeConfiguration();
            final URL defaultConfigUrl = ConfigurationHolder.class.getResource(DEFAULT_CONFIG_FILE);
            try {
                defaultValues.addConfiguration(loadProperties(defaultConfigUrl));
            } catch (ConfigurationException e) {
                log.error("Error encountered when loading default properties. Could not load configuration from " + defaultConfigUrl, e);
            }

            // read cesecore.properties, from config file built into jar, and see if we allow configuration by external files
            boolean allowexternal = false;
            try {
                final URL url = ConfigurationHolder.class.getResource("/conf/"+CONFIG_FILES[0]);
                if (url != null) {
                    final PropertiesConfiguration pc = loadProperties(url);
                    allowexternal = "true".equalsIgnoreCase(pc.getString(CONFIGALLOWEXTERNAL, "false"));
                    log.info("Allow external re-configuration: " + allowexternal);
                }
            } catch (ConfigurationException e) {
                log.error("Error initializing configuration: ", e);
            }
            config = new CompositeConfiguration();

            // Only add these config sources if we allow external configuration
            if (allowexternal) {
                // Override with system properties, this is prio 1 if it exists (java -Dscep.test=foo)
                config.addConfiguration(new SystemConfiguration());
                log.info("Added system properties to configuration source (java -Dfoo.prop=bar).");

                // Override with file in "application server home directory"/bin/conf, this is prio 2
                loadReloadingPropertiesFromExternalDirectory("conf" + File.separator);
                
                // Override with file in "/etc/cesecore/conf/, this is prio 3
                loadReloadingPropertiesFromExternalDirectory("/etc/cesecore/conf/");

            } // if (allowexternal)

            // Default values build into jar file, this is last prio used if no of the other sources override this
            for (int i = 0; i < CONFIG_FILES.length; i++) {
                addConfigurationResource("/conf/"+CONFIG_FILES[i]);
            }
            // Load internal.properties only from built in configuration file
            try {
                final URL url = ConfigurationHolder.class.getResource("/internal.properties");
                if (url != null) {
                    config.addConfiguration(loadProperties(url));
                    log.debug("Added url to configuration source: " + url);
                }
            } catch (ConfigurationException e) {
                log.error("Failed to load configuration from resource internal.properties", e);
            }
        }
        return config;
    }
    
    private static void loadReloadingPropertiesFromExternalDirectory(final String directory) {
        boolean foundAny = false;
        for (int i = 0; i < CONFIG_FILES.length; i++) {
            File file = null;
            try {
                file = new File(directory + CONFIG_FILES[i]);
                if (file.exists()) {
                    if (!file.canRead()) {
                        log.warn("External configuration file '" + file.getAbsolutePath() + "' is present but cannot be read.");
                        continue;
                    }
                    config.addConfiguration(loadReloadingProperties(file));
                    log.info("Added file to configuration source: " + file.getAbsolutePath());
                    foundAny = true;
                }
            } catch (ConfigurationException e) {
                log.error("Failed to load configuration from file " + file.getAbsolutePath() + ": " + e.getMessage());
            }
        }
        if (!foundAny) {
            log.info("External configuration override is allowed, but no configuration sources were detected in '" + new File(directory).getAbsolutePath()  + "'.");
        }
    }
    
    private static synchronized void addConfiguration(final PropertiesConfiguration pc) {
        // The try/catch is needed with commons-configuration 1.10 (but not with 1.06)
//        try {
            final CompositeConfiguration cfgClone = (CompositeConfiguration) config.clone();
            cfgClone.addConfiguration(pc);
            config = cfgClone; // atomic replacement, since we don't want to require all the get*() methods to be synchronized
//        } catch (ConfigurationRuntimeException e) {
//            // Appears to happen due to some bug in MapConfiguration (on certain systems only)
//            if (log.isDebugEnabled()) {
//                log.debug("Configuration class " + config.getClass().getName() + " is not cloneable. Falling back to not fully thread safe code.", e);
//            }
//            config.addConfiguration(pc);
//        }
    }

    /**
     * Method used primarily for JUnit testing, where we can add a new properties file (in tmp directory) to the configuration.
     *
     * @param filename the full path to the properties file used for configuration.
     */
    public static void addConfigurationFile(final String filename) {
        // Make sure the basic initialization has been done
        instance();
        File f = null;
        try {
            f = new File(filename);
            addConfiguration(loadReloadingProperties(f));
            log.info("Added file to configuration source: " + f.getAbsolutePath());
        } catch (ConfigurationException e) {
            log.error("Failed to load configuration from file " + f.getAbsolutePath());
        }
    }

    /**
     * Add built in config file
     */
    public static void addConfigurationResource(final String resourcename) {
        // Make sure the basic initialization has been done
        instance();
        if (log.isDebugEnabled()) {
            log.debug("Add resource to configuration: " + resourcename);
        }
        try {
            final URL url = ConfigurationHolder.class.getResource(resourcename);
            if (url != null) {
                config.addConfiguration(loadProperties(url));
                if (log.isDebugEnabled()) {
                    log.debug("Added url to configuration source: " + url);
                }
            }
        } catch (ConfigurationException e) {
            log.error("Failed to load configuration from resource " + resourcename, e);
        }
    }

    /**
     * @return the configuration as a regular Properties object
     */
    public static Properties getAsProperties() {
        final Properties properties = new Properties();
        final Iterator<?> i = instance().getKeys();
        while (i.hasNext()) {
            final String key = (String) i.next();
            properties.setProperty(key, instance().getString(key));
        }
        return properties;
    }

    /**
     * @param property the property to look for
     * @return String configured for property, or the default value defined in defaultvalues.properties, or null if no such value exists
     */
    public static String getString(final String property) {
     // Commons configuration interprets ','-separated values as an array of Strings, but we need the whole String for example SubjectDNs.
        final StringBuilder str = new StringBuilder();
        String rets[] = instance().getStringArray(property);
        if (rets.length == 0) {
            rets = defaultValues.getStringArray(property);
        }
        for (int i = 0; i < rets.length; i++) {
            if (i != 0) {
                str.append(',');
            }
            str.append(rets[i]);
        }
        final String ret;
        if (str.length() != 0) {
            ret = str.toString();
        } else {
            ret = defaultValues.getString(property);
        }
        return ret;
    }

    /**
     * @param property the property to look for
     * @return String configured for property. If the value is not configured, return null. (DOES NOT LOOK FOR FALLBACK VALUE FROM defaultvalues.properties)
     */
    public static String getConfiguredString(final String property) {
        // Commons configuration interprets ','-separated values as an array of Strings, but we need the whole String for example SubjectDNs.
        final StringBuilder str = new StringBuilder();
        String rets[] = instance().getStringArray(property);
        for (int i = 0; i < rets.length; i++) {
            if (i != 0) {
                str.append(',');
            }
            str.append(rets[i]);
        }
        String ret = null;
        if (str.length() != 0) {
            ret = str.toString();
        }
        return ret;
    }
    
    public static String getDefaultValue(final String property) {
        instance();
        return defaultValues.getString(property);
    }

    public static String[] getDefaultValueArray(final String property) {
        instance();
        return defaultValues.getStringArray(property);
    }

    /**
     * Return a the expanded version of a property. E.g. property1=foo property2=${property1}bar would return "foobar" for property2
     *
     * @param property the property to look for
     * @return String configured for property, or the default value defined in defaultvalues.properties, or null if no such value exists
     */
    public static String getExpandedString(final String property) {
        String ret = getString(property);
        if (ret != null) {
            while (ret.contains("${")) {
                ret = interpolate(ret);
            }
        }
        return ret;
    }

    private static String interpolate(final String orderString) {
        final Pattern PATTERN = Pattern.compile("\\$\\{(.+?)\\}");
        final Matcher m = PATTERN.matcher(orderString);
        final StringBuffer sb = new StringBuffer(orderString.length());
        m.reset();
        while (m.find()) {
            // when the pattern is ${identifier}, group 0 is 'identifier'
            final String key = m.group(1);
            final String value = getExpandedString(key);

            // if the pattern does exists, replace it by its value
            // otherwise keep the pattern ( it is group(0) )
            if (value != null) {
                m.appendReplacement(sb, value);
            } else {
                // I'm doing this to avoid the backreference problem as there will be a $
                // if I replace directly with the group 0 (which is also a pattern)
                m.appendReplacement(sb, "");
                final String unknown = m.group(0);
                sb.append(unknown);
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Given the prefix "something", in a list of properties named "something.NAME.xxx.yyy", returns all
     * unique names (the NAME part only) in sorted order.
     */
    public static List<String> getPrefixedPropertyNames(String prefix) {
        Set<String> algs = new HashSet<>();
        // Just get the keys from configuration that starts with prefix, we assume below that it has a . following the prefix
        Iterator<?> iterator = config.getKeys(prefix);
        while (iterator.hasNext()) {
            final String key = (String) iterator.next();
            final int dot = key.indexOf(".", prefix.length()+1); // +1 to skip the . directly following prefix
            algs.add(key.substring(prefix.length()+1, dot));
        }
        ArrayList<String> list = new ArrayList<>(algs);
        Collections.sort(list);
        return list;
    }

    /**
     * Backups the original configuration in a non thread safe way. This backup stores the current configuration in a variable, this makes it possible
     * to test a configuration change and revert to the original configuration (cancel change). It is used in conjunction with updateConfiguration and
     * restore configuration.
     *
     * Normally used by functional (system) tests, but can also be used to "try" configuraiton settings in a live system.
     */
    public static boolean backupConfiguration() {
        if (configBackup != null) {
            return false;
        }
        instance();
        configBackup = (CompositeConfiguration) config.clone();
        return true;
    }

    /**
     * Restores the original configuration in a non thread safe way. It restores a previously backed up configuration. The backup stores the current
     * configuration in a variable, this makes it possible to test a configuration change and revert to the original configuration (cancel change). It
     * is used in conjunction with updateConfiguration and backup configuration.
     *
     * Normally used by functional (system) tests, but can also be used to "try" configuration settings in a live system.
     */
    public static boolean restoreConfiguration() {
        if (configBackup == null) {
            return false;
        }
        config = configBackup;
        configBackup = null;
        return true;
    }

    /**
     * Takes a backup of the active configuration if necessary and updates the active configuration. Does not persist the configuration change to disk
     * or database, so it is volatile during the running of the application. Persisting the configuration must be handles outside of this method.
     *
     * Normally used by functional (system) tests, but can also be used to "try" configuration settings in a live system.
     */
    public static boolean updateConfiguration(final Properties properties) {
        backupConfiguration(); // Only takes a backup if necessary.
        return updateConfigurationWithoutBackup(properties);
    }

    /**
     * Takes a backup of the active configuration if necessary and updates the active configuration. Does not persist the configuration change to disk
     * or database, so it is volatile during the running of the application. Persisting the configuration must be handles outside of this method.
     *
     * Normally used by functional (system) tests, but can also be used to "try" configuration settings in a live system.
     */
    public static boolean updateConfiguration(final String key, final String value) {
        backupConfiguration(); // Only takes a backup if necessary.
        return updateConfigurationWithoutBackup(key, value);
    }

    /**
     * Updates the active configuration. Does not persist the configuration change to disk or database, so it is volatile during the running of the application.
     * Persisting the configuration must be handles outside of this method.
     */
    public static boolean updateConfigurationWithoutBackup(final Properties properties) {
        for (Object key : properties.keySet()) {

            final String value = (String) properties.get(key);
            config.setProperty((String) key, value);
        }
        return true;
    }

    /**
     * Updates the active configuration. Does not persist the configuration change to disk or database, so it is volatile during the running of the application.
     * Persisting the configuration must be handles outside of this method.
     */
    public static boolean updateConfigurationWithoutBackup(final String key, final String value) {
        config.setProperty(key, value);
        return true;
    }
    
    /**
     * Loads properties by URL.
     * 
     * @param url the URL to the properties file (usually from within the EAB file).
     * @return the properties configuration for the given file or an empty properties configuration.
     * 
     * @throws ConfigurationException if the configuration exists and could not be loaded.
     */
    public static final PropertiesConfiguration loadProperties(final URL url) throws ConfigurationException {
        final FileBasedConfigurationBuilder<PropertiesConfiguration> builder =
                new FileBasedConfigurationBuilder<PropertiesConfiguration>(PropertiesConfiguration.class)
                .configure(new Parameters().properties().setURL(url)
                    .setThrowExceptionOnMissing(false)
                    .setListDelimiterHandler(new LegacyListDelimiterHandler(','))
                    .setIncludesAllowed(false));
        final PropertiesConfiguration config = builder.getConfiguration();
        return config;
    }
    
    /**
     * Loads reloading properties by file.
     * 
     * @param file the properties file (external file, effective if allow.external-dynamic.configuration=true).
     * @return the properties configuration for the given file or an empty properties configuration.
     * 
     * @throws ConfigurationException if the configuration exists and could not be loaded.
     */
    public static final PropertiesConfiguration loadReloadingProperties(final File file) throws ConfigurationException {
        final ReloadingFileBasedConfigurationBuilder<PropertiesConfiguration> builder = 
                new ReloadingFileBasedConfigurationBuilder<PropertiesConfiguration>(PropertiesConfiguration.class)
                .configure(new Parameters().fileBased().setThrowExceptionOnMissing(false)
                        .setFile(file)
                        .setListDelimiterHandler(new LegacyListDelimiterHandler(',')));
        
        builder.addEventListener(ConfigurationBuilderResultCreatedEvent.RESULT_CREATED,
            new EventListener<ConfigurationBuilderEvent>() {
                @SuppressWarnings("unchecked")
                @Override
                public void onEvent(ConfigurationBuilderEvent event) {
                    if (log.isDebugEnabled()) {
                        log.debug("Loaded external configuration file: " + ((ReloadingFileBasedConfigurationBuilder<PropertiesConfiguration>) event.getSource()).getFileHandler().getFile().getAbsolutePath());
                    }
                }
            }
        );
        
        final InternalPeriodicReloadingTrigger trigger = new InternalPeriodicReloadingTrigger(builder, null, 1, TimeUnit.MINUTES);
        trigger.start();
        
        final PropertiesConfiguration config = builder.getConfiguration();
        return config;
    }
    
    private static class InternalPeriodicReloadingTrigger
    {
        /** The executor service used by this trigger. */
        private final ScheduledExecutorService executorService;

        /** The associated reloading controller. */
        private final ReloadingController controller;

        /** The parameter to be passed to the controller. */
        private final Object controllerParam;

        /** The period. */
        private final long period;

        /** The time unit. */
        private final TimeUnit timeUnit;

        /** Stores the future object for the current trigger task. */
        private ScheduledFuture<?> triggerTask;
        
        /** Reference to the builder. */
        private ReloadingFileBasedConfigurationBuilder<PropertiesConfiguration> builder;

        /**
         * Creates a new instance of {@code PeriodicReloadingTrigger} and sets all
         * parameters.
         *
         * @param builder the builder
         * @param ctrlParam the optional parameter to be passed to the controller
         *        when doing reloading checks
         * @param triggerPeriod the period in which the controller is triggered
         * @param unit the time unit for the period
         * @param exec the executor service to use (can be <b>null</b>, then a
         *        default executor service is created
         * @throws IllegalArgumentException if a required argument is missing
         */
        public InternalPeriodicReloadingTrigger(final ReloadingFileBasedConfigurationBuilder<PropertiesConfiguration> builder, final Object ctrlParam,
                final long triggerPeriod, final TimeUnit unit, final ManagedScheduledExecutorService exec)
        {
            if (builder.getReloadingController() == null)
            {
                throw new IllegalArgumentException(
                        "ReloadingController must not be null!");
            }
            this.builder = builder;
            controller = builder.getReloadingController();
            controllerParam = ctrlParam;
            period = triggerPeriod;
            timeUnit = unit;
            executorService =
                    exec != null ? exec : createDefaultExecutorService();
        }

        /**
         * Creates a new instance of {@code PeriodicReloadingTrigger} with a default
         * executor service.
         *
         * @param builder the builder
         * @param ctrlParam the optional parameter to be passed to the controller
         *        when doing reloading checks
         * @param triggerPeriod the period in which the controller is triggered
         * @param unit the time unit for the period
         * @throws IllegalArgumentException if a required argument is missing
         */
        public InternalPeriodicReloadingTrigger(ReloadingFileBasedConfigurationBuilder<PropertiesConfiguration> builder, final Object ctrlParam,
                final long triggerPeriod, final TimeUnit unit)
        {
            this(builder, ctrlParam, triggerPeriod, unit, null);
        }

        /**
         * Starts this trigger. The associated {@code ReloadingController} will be
         * triggered according to the specified period. The first triggering happens
         * after a period. If this trigger is already started, this invocation has
         * no effect.
         */
        public synchronized void start()
        {
            if (!isRunning())
            {
                triggerTask =
                        getExecutorService().scheduleAtFixedRate(
                                createTriggerTaskCommand(), period, period,
                                timeUnit);
            }
        }

        /**
         * Stops this trigger. The associated {@code ReloadingController} is no more
         * triggered. If this trigger is already stopped, this invocation has no
         * effect.
         */
        public synchronized void stop()
        {
            if (isRunning())
            {
                triggerTask.cancel(false);
                triggerTask = null;
            }
        }

        /**
         * Returns a flag whether this trigger is currently active.
         *
         * @return a flag whether this trigger is running
         */
        public synchronized boolean isRunning()
        {
            return triggerTask != null;
        }

        /**
         * Shuts down this trigger and optionally shuts down the
         * {@code ScheduledExecutorService} used by this object. This method should
         * be called if this trigger is no more needed. It ensures that the trigger
         * is stopped. If the parameter is <b>true</b>, the executor service is also
         * shut down. This should be done if this trigger is the only user of this
         * executor service.
         *
         * @param shutdownExecutor a flag whether the associated
         *        {@code ScheduledExecutorService} is to be shut down
         */
        public void shutdown(final boolean shutdownExecutor)
        {
            stop();
            if (shutdownExecutor)
            {
                if(log.isTraceEnabled()) {
                    final String path = builder.getFileHandler().getFile().getAbsolutePath();
                    log.trace("Shutdown executor service for external configuration '" + path + "'.");
                }
                getExecutorService().shutdown();
            }
        }

        /**
         * Shuts down this trigger and its {@code ScheduledExecutorService}. This is
         * a shortcut for {@code shutdown(true)}.
         *
         * @see #shutdown(boolean)
         */
        public void shutdown() {
            shutdown(true);
        }

        /**
         * Returns the {@code ScheduledExecutorService} used by this object.
         *
         * @return the associated {@code ScheduledExecutorService}
         */
        ScheduledExecutorService getExecutorService() {
            return executorService;
        }

        /**
         * Creates the task which triggers the reloading controller.
         *
         * @return the newly created trigger task
         */
        private Runnable createTriggerTaskCommand()
        {
            return () -> {
                final String path = builder.getFileHandler().getFile().getAbsolutePath();
                final boolean reloadingRequired = controller.getDetector().isReloadingRequired();
                if(log.isTraceEnabled()) {
                    log.trace("External configuration '" + path + "' requires reload " + reloadingRequired);
                }
                controller.checkForReloading(controllerParam);
                
                if (reloadingRequired) {
                    try {
                        if(log.isDebugEnabled()) {
                            // Successful reloading triggers the builders event listener (type RESULT_CREATED).
                            log.debug("Try to reload external configuration '" + builder.getFileHandler().getFile().getAbsolutePath() + "'.");
                        }
                        builder.resetResult();
                        config.copy(builder.getConfiguration());
                        builder.getReloadingController().resetReloadingState();
                    } catch (ConfigurationException e) {
                        log.error("Failed reloading external configuration '" + path + "': " + e.getMessage());
                        if(log.isTraceEnabled()) {
                            log.trace(e);
                        }
                    }
                }
            };
        }

        /**
         * Creates a default executor service. This method is called if no executor
         * has been passed to the constructor.
         *
         * @return the default executor service
         */
        private static ScheduledExecutorService createDefaultExecutorService()
        {
            final ThreadFactory factory =
                    new BasicThreadFactory.Builder()
                            .namingPattern("ReloadingTrigger-%s").daemon(true)
                            .build();
            return Executors.newScheduledThreadPool(2, factory);
        }
    }
}
