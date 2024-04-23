package co.istad.mobilebankingcstad.config;

import co.istad.mobilebankingcstad.security.JwtToUserConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
//@EnableWebSecurity
public class SecurityConfiguration {
    private JwtToUserConverter jwtToUserConverter;

    // configure securityfilter chain
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(
                        (authz) ->
                                authz
                                        // allow all resources regarding  swagger ui
                                        .requestMatchers("/",
                                                "/v3/api-docs/**",
                                                "/swagger-ui/**",
                                                "/v2/api-docs/**",
                                                "/swagger-resources/**")
                                        .permitAll()
                                        .requestMatchers("/api/v1/auth/**")
                                        .permitAll()
                                        // since user will need to upload the picture in order to register
                                        .requestMatchers(
                                                "api/v1/files/**",
                                                "images/**")
                                        .permitAll()
                                        .anyRequest().authenticated()
                )
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(Customizer.withDefaults())
                .oauth2ResourceServer((auth2) -> auth2.jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtToUserConverter)))
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling((ex) -> ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                        .accessDeniedHandler(new BearerTokenAccessDeniedHandler()))
                // to make the session to stateless
//                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }

}
