package com.weareadaptive.nexus.casc.plugin.internal.config;

import java.util.ArrayList;
import java.util.List;

public class ConfigSecurityRole {
    private Boolean enabled;
    private String id;
    private String source;
    private String name;
    private String description;
    private List<String> privileges = new ArrayList<String>();
    private List<String> roles = new ArrayList<String>();

    public Boolean isEnabled() { return enabled; }
    public Boolean getEnabled() { return enabled; }

    public void setEnabled(Boolean enabled) { this.enabled = enabled; }

    public String getId() { return this.id; }

    public void setId(String id) { this.id = id; }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

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

    public List<String> getPrivileges() {
        return privileges;
    }

    public void setPrivileges(List<String> privileges) {
        this.privileges = privileges;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
