package com.programandoenjava.jwt.filter;

import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Order(1)
@RequiredArgsConstructor
public class TraceIdFilter implements Filter {

    private static final String TRACE_ID_HEADER = "X-Trace-Id";
    private static final String SPAN_ID_HEADER = "X-Span-Id";
    private static final String TRACE_ID_MDC_KEY = "traceId";
    private static final String SPAN_ID_MDC_KEY = "spanId";

    private final Tracer tracer;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String requestPath = httpRequest.getRequestURI();
        if (requestPath.startsWith("/actuator")) {
            chain.doFilter(request, response);
            return;
        }

        Span currentSpan = tracer.currentSpan();

        if (currentSpan != null && currentSpan.context() != null) {
            String traceId = currentSpan.context().traceId();
            String spanId = currentSpan.context().spanId();

            MDC.put(TRACE_ID_MDC_KEY, traceId);
            MDC.put(SPAN_ID_MDC_KEY, spanId);

            httpResponse.setHeader(TRACE_ID_HEADER, traceId);
            httpResponse.setHeader(SPAN_ID_HEADER, spanId);

            currentSpan.tag("http.method", httpRequest.getMethod());
            currentSpan.tag("http.path", requestPath);
            currentSpan.tag("http.url", httpRequest.getRequestURL().toString());
        }

        try {
            chain.doFilter(request, response);

            if (currentSpan != null) {
                currentSpan.tag("http.status_code", String.valueOf(httpResponse.getStatus()));
            }
        } finally {
            MDC.remove(TRACE_ID_MDC_KEY);
            MDC.remove(SPAN_ID_MDC_KEY);
        }
    }
}