package com.cas.handler;

import com.cas.entity.SysUser;
import com.cas.utils.PasswordUtils;
import org.apereo.cas.authentication.*;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SysUserLoginHandler extends AbstractUsernamePasswordAuthenticationHandler {

    private static final Logger logger = LoggerFactory.getLogger(SysUserLoginHandler.class);
    @Value("${jdbc.url}")
    public String url;
    @Value("${jdbc.driverClassName}")
    String driverClassName;
    @Value("${jdbc.username}")
    String username;
    @Value("${jdbc.password}")
    String password;

    public SysUserLoginHandler(String name, ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    @Override
    protected AuthenticationHandlerExecutionResult doAuthentication(Credential credential) throws GeneralSecurityException, PreventedException {

        UsernamePasswordCredential myCredential=(UsernamePasswordCredential) credential;
        logger.info(myCredential.getPassword());
        // 验证用户名和密码
        DriverManagerDataSource d = new DriverManagerDataSource();
        d.setDriverClassName(driverClassName);
        d.setUrl(url);
        d.setUsername(username);
        d.setPassword(password);

        JdbcTemplate template = new JdbcTemplate();
        template.setDataSource(d);

        // 查询数据库加密的的密码
        String sql="select * from v_sso_sys_user where username=? ";
        List<SysUser> sysUserList=template.query(sql,new BeanPropertyRowMapper<SysUser>(SysUser.class),myCredential.getUsername());

        if (sysUserList==null||sysUserList.size()==0) {
            throw new AccountNotFoundException("用户名不存在");
        }
        boolean flag=false;

           /* try {
                String encryptPassword = DESUtil.decryption(myCredential.getPassword());
                for(SysUser sysUser:sysUserList){
                    String userpassword = PasswordUtils.encrypt(myCredential.getUsername(), encryptPassword, sysUser.getSalt());
                    if (sysUser.getPassword().equals(userpassword)){
                        flag=true;
                    }
                }
            } catch (Exception e) {
                throw new FailedLoginException("密码解密错误");
            }*/

            for(SysUser sysUser:sysUserList){
                String userpassword = PasswordUtils.encrypt(myCredential.getUsername(), myCredential.getPassword(), sysUser.getSalt());
                if (sysUser.getPassword().equals(userpassword)){
                    flag=true;
                }
            }



        // 返回多属性
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("username", myCredential.getUsername());
        List<MessageDescriptor>  warning = new ArrayList<MessageDescriptor>();
        if(flag){
            return createHandlerResult(myCredential, principalFactory.createPrincipal(myCredential.getUsername(), map),warning);
        }

        throw new FailedLoginException("密码输入错误");

    }

    @Override
    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential, String originalPassword) throws GeneralSecurityException, PreventedException {
        return null;
    }


}
