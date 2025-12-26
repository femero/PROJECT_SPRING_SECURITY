package com.programandoenjava.jwt.util;

public enum Permission {
    ACCOUNTS_READ("accounts:read"),
    ACCOUNTS_WRITE("accounts:write"),
    TRANSFERS_CREATE("transfers:create"),
    BENEFICIARIES_MANAGE("beneficiaries:manage");

    private final String scope;

    Permission(String scope) {
        this.scope = scope;
    }

    public String getScope() {
        return scope;
    }
}