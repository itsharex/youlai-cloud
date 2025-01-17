package com.youlai.auth.config;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.json.JSONUtil;
import com.youlai.auth.property.CustomSecurityProperties;
import com.youlai.common.result.Result;
import com.youlai.common.result.ResultCode;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 默认安全配置
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class SecurityConfig {


    private final CustomSecurityProperties customSecurityProperties;

    private final CorsFilter corsFilter;

    /**
     * Spring Security 安全过滤器链配置
     *
     * @param http 安全配置
     * @return 安全过滤器链
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
        http.addFilter(corsFilter);

        // 禁用 csrf 与 cors
        http.csrf(AbstractHttpConfigurer::disable);


        MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
        http.authorizeHttpRequests((requests) ->
                        {
                            if (CollectionUtil.isNotEmpty(customSecurityProperties.getWhitelistPaths())) {
                                for (String whitelistPath : customSecurityProperties.getWhitelistPaths()) {
                                    requests.requestMatchers(mvcMatcherBuilder.pattern(whitelistPath)).permitAll();
                                }
                            }
                            requests.anyRequest().authenticated();
                        }
                )
                .csrf(AbstractHttpConfigurer::disable)
                // 登录页面配置
                .formLogin(
                        formLogin -> {
                            formLogin.loginPage("/login");

                            // 如果是绝对路径，表示是前后端分离的登录页面，需要重写登录成功和失败为 JSON 格式
                            if(UrlUtils.isAbsoluteUrl(customSecurityProperties.getLoginUrl())){
                                formLogin.successHandler((request, response, authentication) -> {
                                    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                                    response.getWriter().write(JSONUtil.toJsonStr(Result.success()));
                                });
                                formLogin.failureHandler((request, response, exception) -> {
                                    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                                    response.getWriter().write(JSONUtil.toJsonStr(Result.failed(ResultCode.AUTHORIZED_ERROR,exception.getMessage())));
                                });
                            }
                        }
                );

        return http.build();
    }


    /**
     * 不走过滤器链的放行配置
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(
                AntPathRequestMatcher.antMatcher("/webjars/**"),
                AntPathRequestMatcher.antMatcher("/assets/**"),
                AntPathRequestMatcher.antMatcher("/doc.html"),
                AntPathRequestMatcher.antMatcher("/swagger-resources/**"),
                AntPathRequestMatcher.antMatcher("/v3/api-docs/**"),
                AntPathRequestMatcher.antMatcher("/swagger-ui/**")
        );
    }


}
