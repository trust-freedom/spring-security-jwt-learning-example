package com.freedom.auth.security;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 认证成功处理器
 */
@Component
public class JWTAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler implements InitializingBean {

    @Autowired
    private JwtTokenProvider tokenProvider;

    // 登录成功后页面
    @Value("${app.loginSuccessPage}")
    private String loginSuccessPage;

    public JWTAuthenticationSuccessHandler(){
        // 向SimpleUrlAuthenticationSuccessHandler注册defaultTargetUrl
        //super("/hello");
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        this.setDefaultTargetUrl(loginSuccessPage);
    }

    /**
     * 认证成功后的处理
     * @param request
     * @param response
     * @param authentication
     * @throws ServletException
     * @throws IOException
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        // 生成JWT
        String jwt = tokenProvider.generateToken(authentication);

        // 放入cookie
        Cookie cookie = new Cookie("jwt_cookie", jwt);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);

        // 调用父类，实现跳转
        super.onAuthenticationSuccess(request, response, authentication);
    }

}
