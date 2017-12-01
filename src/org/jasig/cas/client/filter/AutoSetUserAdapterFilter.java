package org.jasig.cas.client.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Assertion;
import org.springframework.jdbc.core.JdbcTemplate;

import com.tom.WebAppConfig;
import com.tom.core.util.SystemLoggerHelper;
import com.tom.system.service.IAdminRoleService;
import com.tom.system.service.IAdminService;
import com.tom.system.service.IUserService;
import com.tom.user.dao.ICommonDao;
import com.tom.util.BaseUtil;
import com.tom.util.CacheHelper;
import com.tom.util.Constants;
import com.tom.util.IPUtil;
import com.tom.util.Md5Util;
import com.tom.util.WebApplication;

public class AutoSetUserAdapterFilter implements Filter {

	
	private static final Logger logger = Logger.getLogger(AutoSetUserAdapterFilter.class);
	
	@Override
	public void destroy() {

	}


	private Map<String, Object> getUserByUserName(String usertype, String username) {
		String sql = "select * from tm_user where u_username=?";
		if ("1".equals(usertype)) {
			sql = "select * from tm_admin where a_username=?";
		}

		JdbcTemplate service = (JdbcTemplate) SpringContextHelper.getBean("jdbcTemplate");
		Map map  = null;
		try{
			 map = service.queryForMap(sql, new Object[] { username });
		}catch (Exception e) {
			e.printStackTrace();
		}
		
		if (map == null) {
			return null;
		}
		String userid = null;
		String userstatus = null;
		String usersalt = null;
		String userpass = null;
		String usergid = null;

		Map user = new HashMap();
		String tomUserType = "0";
		if (!"6".equals(usertype)) {
			tomUserType = "1";
			userid = String.valueOf(map.get("a_id"));
			userstatus = String.valueOf(map.get("a_status"));
			usersalt = String.valueOf(map.get("a_salt"));
			userpass = String.valueOf(map.get("a_userpass"));
			usergid = String.valueOf(map.get("a_roleid"));
		} else {
			userid = String.valueOf(map.get("u_id"));
			userstatus = String.valueOf(map.get("u_status"));
			usersalt = String.valueOf(map.get("u_salt"));
			userpass = String.valueOf(map.get("u_userpass"));
			usergid = String.valueOf(map.get("u_branchid"));
		}

		user.put("user_id", userid);
		user.put("user_name", username);
		user.put("user_type", tomUserType);
		user.put("user_status", userstatus);
		user.put("user_salt", usersalt);
		user.put("user_pass", userpass);
		user.put("user_gid", usergid);

		return user;
	 }

	
	public Map<String, Object> doLogin(String usertype, String username, String userpass) {
		logger.info(String.format("用户登录，username=%s，usertype=%s", new Object[] { username, usertype }));

		Map ret = new HashMap();

		if ((BaseUtil.isEmpty(usertype)) || (BaseUtil.isEmpty(username)) || (BaseUtil.isEmpty(userpass))) {
			ret.put("code", Integer.valueOf(-4));
			ret.put("msgkey", "params_required");
			return ret;
		}
		try {
			Map user = getUserByUserName(usertype, username);

			if (user == null) {
				ret.put("code", Integer.valueOf(-3));
				ret.put("msgkey", "user_not_exsit");
				return ret;
			}

			String status = String.valueOf(user.get("user_status"));
			if ("-1".equals(status)) {
				ret.put("code", Integer.valueOf(-2));
				ret.put("msgkey", "user_locked");
				return ret;
			}

			
			String userid = String.valueOf(user.get("user_id"));
			updateUserLastLogin(usertype, userid);

			ret.put("code", Integer.valueOf(1));
			ret.put("data", user);
			ret.put("msgkey", "success");
			return ret;
		} catch (Exception e) {
			logger.error(e);
			ret.put("code", Integer.valueOf(-9));
			ret.put("msgkey", "unknown_error");
		}
		return ret;
	}
	
	private int updateUserLastLogin(String usertype, String userid)
	{
		JdbcTemplate service = (JdbcTemplate) SpringContextHelper.getBean("jdbcTemplate");
		 if ("1".equals(usertype)) {
		 String sql = "update tm_admin_addition set a_logintimes=a_logintimes+1 , a_lastlogin=now() where a_id=?";
		 return service.update(sql, new Object[] { userid });
		 }
		 String sql = "update tm_user_addition set u_logintimes=u_logintimes+1 , u_lastlogin=now() where u_id=?";
		 return service.update(sql, new Object[] { userid });
	 }
	
	
	public final void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
			final FilterChain filterChain) throws IOException, ServletException {
		final HttpServletRequest request = (HttpServletRequest) servletRequest;
		final HttpServletResponse response = (HttpServletResponse) servletResponse;
		final HttpSession session = request.getSession(false);
		final Assertion assertion = session != null
				? (Assertion) session.getAttribute(org.jasig.cas.client.util.AbstractCasFilter.CONST_CAS_ASSERTION)
				: null;
		AttributePrincipal principal = (AttributePrincipal) request.getUserPrincipal();

		java.util.Map<String, Object> attributes = principal.getAttributes();
		if (attributes != null && attributes.size() > 0) {

			String loginname = attributes.get("login_name").toString();
			ICommonDao commonDao = (ICommonDao) SpringContextHelper.getBean("commonDaoImp");
			IUserService userService = (IUserService) SpringContextHelper.getBean("UserService");

			Map<String, Object> paramMap = new HashMap<String, Object>();

			// 判断当前登录用户是否存在,如果不存在创建用户.如果存在继续相关业务操作

			// [{roleId=6}]

			
			String usertype = (String)attributes.get("userType");
		

			String randPwd = randomPassword();
			
			if (!org.apache.commons.lang.StringUtils.isEmpty(usertype)&&usertype.equals("6")) {
				
				if (!userService.doCheckUsernameExist(loginname)) {
					paramMap.put("u_username", loginname);
					paramMap.put("u_userpass", randPwd);
					paramMap.put("u_branchid", attributes.get("office_id"));
					paramMap.put("u_positionid", attributes.get("userType"));
					paramMap.put("u_realname", attributes.get("name"));
					paramMap.put("u_no", attributes.get("login_name"));
					paramMap.put("u_phone", attributes.get("mobile"));
					paramMap.put("u_photo", "");
					paramMap.put("u_score", "0");
					paramMap.put("u_address", "");
					paramMap.put("u_remark", "在线考试系统注册");
					paramMap.put("u_email", attributes.get("email"));
					paramMap.put("u_status", 1);
					
					
					userService.addUser(paramMap);
				}
				
			} else {
				IAdminService adminService = (IAdminService) SpringContextHelper.getBean("AdminService");

				boolean ret = adminService.doCheckUsernameExist(loginname);
				if (!ret) {
					paramMap.put("a_username", loginname);
					String userpass = randPwd;
					String salt = BaseUtil.generateRandomString(10);
					if (BaseUtil.isNotEmpty(userpass)) {
						String password = ((Md5Util) WebApplication.getInstance().getSingletonObject(Md5Util.class))
								.getMD5ofStr(Constants.SYS_IDENTIFICATION_CODE + userpass + salt);
						paramMap.put("a_userpass", password);
					}
					String teacherRoleId = WebAppConfig.GLOBAL_CONFIG_PROPERTIES.getProperty("teacherRoleId");		
					paramMap.put("a_salt", salt);
					paramMap.put("a_roleid", teacherRoleId);
					paramMap.put("a_username", attributes.get("login_name"));
					paramMap.put("a_realname", attributes.get("name"));
					paramMap.put("a_photo", "");
					paramMap.put("a_phone", attributes.get("mobile"));
					paramMap.put("a_email", attributes.get("email"));
					paramMap.put("a_status", 1);
					paramMap.put("a_remark", "");
					try {
						adminService.addAdmin(paramMap);
					} catch (Exception e) {
						e.printStackTrace();
					}

				}

				
			}
			Map map = doLogin(usertype, loginname,randPwd);
			String scode = String.valueOf(map.get("code"));
			String msgkey = String.valueOf(map.get("msgkey"));
			int code = BaseUtil.getInt(scode);

			if (code == 1) {
				Object object = map.get("data");
				if (object != null) {
					Map user = (Map) object;
					String sessionid = BaseUtil.generateRandomString(20);
					String uid = String.valueOf(user.get("user_id"));
					String usergid = String.valueOf(user.get("user_gid"));
					session.setAttribute(Constants.SESSION_USERID, uid);
					session.setAttribute(Constants.SESSION_USERNAME, String.valueOf(user.get("user_name")));
					session.setAttribute(Constants.SESSION_USERTYPE, String.valueOf(user.get("user_type")));
					session.setAttribute(Constants.SESSION_USERGID, usergid);
					session.setAttribute(Constants.SESSION_SESSID, sessionid);
					session.setAttribute(Constants.SESSION_USERSTATUS, String.valueOf(user.get("user_status")));
					CacheHelper.addCache("SessionCache", "U" + uid, sessionid);
					SystemLoggerHelper.Log(BaseUtil.getInt(usertype), loginname, "doLogin", request.getRequestURI(),
							"登录成功(login_success)", IPUtil.getUserIP(request));

					IAdminRoleService adminRoleService = (IAdminRoleService) SpringContextHelper
							.getBean("AdminRoleService");
					if (usertype.equals("1") && usergid != null){
						Map<String, Object> mm = adminRoleService.getAdminRole(usergid);
						String roleid = String.valueOf(mm.get("r_id"));
						String privilege = String.valueOf(mm.get("r_privilege"));
						CacheHelper.addCache("RoleCache", "R" + roleid, "," + privilege);
					}
					
				} 
			}

		}
		filterChain.doFilter(request, response);
	}
	
	private String randomPassword(){
		return String.valueOf((int)((Math.random()*9+1)*100000));
	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {
		

	}

}
