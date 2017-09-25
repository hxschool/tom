package com.tom.util;

import javax.servlet.http.HttpServletRequest;

public class IPUtil {
	  public static String getUserIP(HttpServletRequest request)
	  {
	    String strUserIp = "127.0.0.1";

	    try
	    {
	      strUserIp = request.getHeader("X-Forwarded-For");
	      if ((strUserIp == null) || (strUserIp.length() == 0) || ("unknown".equalsIgnoreCase(strUserIp))) {
	        strUserIp = request.getHeader("Proxy-Client-IP");
	      }
	      if ((strUserIp == null) || (strUserIp.length() == 0) || ("unknown".equalsIgnoreCase(strUserIp))) {
	        strUserIp = request.getHeader("WL-Proxy-Client-IP");
	      }
	      if ((strUserIp == null) || (strUserIp.length() == 0) || ("unknown".equalsIgnoreCase(strUserIp))) {
	        strUserIp = request.getRemoteAddr();

	      }

	      if (strUserIp != null)
	        strUserIp = strUserIp.split(",")[0];
	      else {
	        strUserIp = "127.0.0.1";

	      }

	      if (strUserIp.length() > 16)
	        strUserIp = "127.0.0.1";
	    }
	    catch (Exception e) {
	      System.err.println("获取用户IP失败");
	    }

	    return strUserIp;
	  }
}
