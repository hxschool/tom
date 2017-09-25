package com.tom.system.action;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.tom.WebAppConfig;
import com.tom.model.system.BaseMessage;
import com.tom.system.service.IBranchService;
import com.tom.util.Constants;
import com.tom.web.controller.BaseController;
/**
 * 未来版本同居数据中心,这个版本暂时不同步数据中心
 * @author Team
 *
 */
@Controller
@RequestMapping({ "/system/config" })
public class GreathiitController extends BaseController {
	@Autowired
	private IBranchService service;
	
	@RequestMapping({ "/common/dataCenter.thtml" })
	public ModelAndView about(HttpServletRequest request, ModelMap modelMap) {
		modelMap.put("systemid", Constants.getSystemId());
		return new ModelAndView("common/about", modelMap);
	}

	@RequestMapping({ "/dataCenter.do" })
	public ModelAndView save(HttpServletRequest request, ModelMap modelMap) {
		if (!(HasPrivelege(request, "P-BRANCH-ADD"))) {
			return RedirectToNoPrivelegePage();
		}
		BaseMessage message = null;

		// propertyConfigurer
		String dataCenter = WebAppConfig.GLOBAL_CONFIG_PROPERTIES.getProperty("data.center.url");		
		return new ModelAndView("common/message", modelMap);
	}

}
