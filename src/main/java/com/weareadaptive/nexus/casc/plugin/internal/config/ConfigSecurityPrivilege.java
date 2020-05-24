package com.weareadaptive.nexus.casc.plugin.internal.config;

import java.util.HashMap;
import java.util.Map;

public class ConfigSecurityPrivilege {
    private boolean enabled;
    private String id;
    private String name;
    private String description;
    private String type;
    private Map<String, String> properties = new HashMap<String, String>();
    private boolean readOnly;

    public boolean getEnabled() {
        return this.enabled;
    }
    public boolean isEnabled() {
        return this.enabled;
    }

    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getId() { return this.id; }

    public void setId(String id) { this.id = id; }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Map<String, String> getProperties() { return this.properties; }

    public boolean getReadOnly() {
        return this.readOnly;
    }
    public boolean isReadOnly() {
        return this.readOnly;
    }

    public void setReadOnly(boolean readOnly) {
        this.readOnly = readOnly;
    }

    public void setProperties(Map<String, String> properties) { this.properties = properties; }
}
