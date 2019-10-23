package com.alibaba.nacos.console.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

/**
 * nacos.client.config 认证过滤器 参考 SpasAdapter ServerHttpAgent
 * SpasAdapter ServerHttpAgent设计不具可扩展性，为了减少后续更新nacos的合并工作量，尽可能少对原有nacos代码进行改动
 *
 * @author CharlesHe
 */
public class ConfigSpasAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(ConfigSpasAuthenticationFilter.class);

    private UserDetailsService userDetailsService;

    public ConfigSpasAuthenticationFilter(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String accessKey = request.getHeader("Spas-AccessKey");
        String signature = request.getHeader("Spas-Signature");
        if (StringUtils.hasText(accessKey) && StringUtils.hasText(signature)) {
            UserDetails user = userDetailsService.loadUserByUsername(accessKey);
            String timestamp = request.getHeader("Timestamp");
            String tenant = request.getParameter("tenant");
            String group = request.getParameter("group");

            String resource = "";
            if (StringUtils.hasText(tenant) && StringUtils.hasText(group)) {
                resource = tenant + "+" + group;
            } else if (StringUtils.hasText(group)) {
                resource = group;
            }

            String calculateSignature = "";
            if (StringUtils.hasText(resource)) {
                calculateSignature = signWithhmacSHA1Encrypt(resource + "+" + timestamp, user.getPassword());
            } else {
                calculateSignature = signWithhmacSHA1Encrypt(timestamp, user.getPassword());
            }

            if (signature.equals(calculateSignature)) {
                fillSecurityContext(user);
                chain.doFilter(request, response);
                return;
            } else {
                logger.info("认证失败 accessKey:{}", accessKey);
            }
        }

        chain.doFilter(request, response);
    }

    public static String signWithhmacSHA1Encrypt(String encryptText, String encryptKey) {
        try {
            byte[] data = encryptKey.getBytes("UTF-8");
            // 根据给定的字节数组构造一个密钥,第二参数指定一个密钥算法的名称
            SecretKey secretKey = new SecretKeySpec(data, "HmacSHA1");
            // 生成一个指定 Mac 算法 的 Mac 对象
            Mac mac = Mac.getInstance("HmacSHA1");
            // 用给定密钥初始化 Mac 对象
            mac.init(secretKey);
            byte[] text = encryptText.getBytes("UTF-8");
            byte[] textFinal = mac.doFinal(text);
            // 完成 Mac 操作, base64编码，将byte数组转换为字符串
            return Base64Utils.encodeToString(textFinal);
        } catch (Exception e) {
            throw new RuntimeException("signWithhmacSHA1Encrypt fail", e);
        }
    }

    private void fillSecurityContext(UserDetails user) {
        User principal = new User(user.getUsername(), "", Collections.emptyList());
        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, "", Collections.emptyList());

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
