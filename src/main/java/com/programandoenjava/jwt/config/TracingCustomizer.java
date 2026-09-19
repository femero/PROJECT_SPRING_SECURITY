package com.programandoenjava.jwt.config;

import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public class TracingCustomizer {

    private final Tracer tracer;

    public void addTag(String key, String value) {
        Span currentSpan = tracer.currentSpan();
        if (currentSpan != null) {
            currentSpan.tag(key, value);
        }
    }

    public void addEvent(String eventName) {
        Span currentSpan = tracer.currentSpan();
        if (currentSpan != null) {
            currentSpan.event(eventName);
        }
    }

    public String getCurrentTraceId() {
        Span currentSpan = tracer.currentSpan();
        if (currentSpan != null && currentSpan.context() != null) {
            return currentSpan.context().traceId();
        }
        return null;
    }

    public String getCurrentSpanId() {
        Span currentSpan = tracer.currentSpan();
        if (currentSpan != null && currentSpan.context() != null) {
            return currentSpan.context().spanId();
        }
        return null;
    }
}