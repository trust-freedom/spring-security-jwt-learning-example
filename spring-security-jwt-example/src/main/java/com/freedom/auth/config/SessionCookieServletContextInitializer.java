package com.freedom.auth.config;

import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.stereotype.Component;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;

@Component
public class SessionCookieServletContextInitializer implements ServletContextInitializer {

    /**
     * 实现ServletContextInitializer，用于自定义cookie
     * 修改默认JSESSIONID名
     */
    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {
        servletContext.getSessionCookieConfig().setName("default_servlet_container_cookie");
        servletContext.getSessionCookieConfig().setHttpOnly(true);
    }

}
