package com.programandoenjava.jwt.util;

public enum Permission {
    READ_ALL_USERS,
    WRITE_ALL_USERS,
    DELETE_ALL_USERS;

    private Permission() {
        // Constructor is private to prevent instantiation
    }
}