package com.programandoenjava.jwt.config;

import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.aop.ObservedAspect;
import io.micrometer.tracing.Tracer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(value = "tracing.enabled", havingValue = "true", matchIfMissing = true)
public class TracingConfig {

    private final Environment environment;

    @Bean
    public ObservedAspect observedAspect(ObservationRegistry observationRegistry) {
        log.info("🔍 Configurando ObservedAspect para instrumentación automática");
        return new ObservedAspect(observationRegistry);
    }

    @Bean
    public TracingCustomizer tracingCustomizer(Tracer tracer) {
        log.info("🔍 Configurando TracingCustomizer");
        String serviceName = environment.getProperty("otel.service.name", "jwt-spring-security");
        String otlpEndpoint = environment.getProperty("otel.exporter.otlp.endpoint", "http://localhost:4318");

        log.info("📊 Tracing habilitado para servicio: {}", serviceName);
        log.info("📡 Exportando traces a: {}", otlpEndpoint);

        return new TracingCustomizer(tracer);
    }
}