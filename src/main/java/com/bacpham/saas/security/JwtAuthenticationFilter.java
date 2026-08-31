package com.bacpham.saas.security;

import com.bacpham.saas.config.TenantContext;
import com.bacpham.saas.config.TenantSchemaResolver;
import io.jsonwebtoken.Claims;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;
    private final TenantSchemaResolver tenantSchemaResolver;

    @Override
    protected void doFilterInternal(
            @Nonnull final HttpServletRequest request,
            @Nonnull final HttpServletResponse response,
            @Nonnull final FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            final String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt)) {
                // Parse và Validate token duy nhất 1 lần
                final Claims claims = this.jwtTokenService.validateAndGetClaims(jwt);

                final String userId = claims.getSubject();
                final String tenantId = claims.get("tenant_id", String.class);
                final String role = claims.get("role", String.class);

                // Set thông tin Tenant cho ThreadLocal
                if (StringUtils.hasText(tenantId)) {
                    TenantContext.setCurrentTenant(tenantId);
                    final String schemaName = this.tenantSchemaResolver.resolveTenantSchema(tenantId);
                    TenantContext.setCurrentSchema(schemaName);
                }

                // Xử lý GrantedAuthority an toàn (tránh NullPointerException nếu role null)
                final List<SimpleGrantedAuthority> authorities = StringUtils.hasText(role)
                        ? Collections.singletonList(new SimpleGrantedAuthority(role))
                        : Collections.emptyList();

                // Tạo đối tượng Authentication trong Spring Security
                final UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userId,
                                null,
                                authorities
                        );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("Authenticated user ID:{}, tenant: {}, role: {}", userId, tenantId, role);
            }
        } catch (final Exception e) {
            log.error("Authentication failed: {}", e.getMessage());
            SecurityContextHolder.clearContext(); // Dọn dẹp context nếu xác thực thất bại
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            // Luôn luôn giải phóng ThreadLocal để tránh leak dữ liệu giữa các request
            TenantContext.clear();
        }
    }

    private String getJwtFromRequest(final HttpServletRequest request) {
        final String authorizationHeader = request.getHeader("Authorization");
        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }
}