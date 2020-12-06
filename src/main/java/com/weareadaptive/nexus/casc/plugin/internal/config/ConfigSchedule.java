package com.weareadaptive.nexus.casc.plugin.internal.config;

import java.util.HashMap;
import java.util.Map;

public class ConfigSchedule {
    private String scheduleType;
    private Map<String, String> properties = new HashMap<String, String>();

    public String getType() {
        return scheduleType;
    }

    public void setType(final String scheduleType) {
        this.scheduleType = scheduleType;
    }

    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(final Map<String, String> properties) {
        this.properties = properties;
    }
}
