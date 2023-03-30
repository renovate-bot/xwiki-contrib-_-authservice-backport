/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.security.authservice.script;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.AccessDeniedException;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authservice.XWikiAuthServiceComponent;
import org.xwiki.security.authservice.internal.AuthServiceConfiguration;
import org.xwiki.security.authservice.internal.DefaultXWikiAuthServiceComponent;
import org.xwiki.security.script.SecurityScriptService;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiAuthService;

/**
 * The script service used to manipulate the registered {@link XWikiAuthService} instances.
 *
 * @version $Id: 85ca4824a28cf6339c29e5016b827b321209b669 $
 */
@Component
@Named(SecurityScriptService.ROLEHINT + '.' + AuthServiceScriptService.ID)
@Singleton
public class AuthServiceScriptService implements ScriptService
{
    /**
     * The role hint of this component.
     */
    public static final String ID = "authService";

    @Inject
    @Named("context")
    private Provider<ComponentManager> componentManagerProvider;

    @Inject
    @Named("xwikicfg")
    private ConfigurationSource xwikicfg;

    @Inject
    private AuthServiceConfiguration configuration;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private AuthorizationManager authorization;

    private void checkWikiAdmin() throws AccessDeniedException
    {
        XWikiContext xcontext = this.contextProvider.get();

        // Make sure current author has wiki admin right to use this API
        this.authorization.checkAccess(Right.ADMIN, xcontext.getAuthorReference(), xcontext.getWikiReference());
    }

    /**
     * Get the {@link XWikiAuthService} according to {@link XWiki#getAuthService()}.
     * 
     * @return the main {@link XWikiAuthService}
     * @throws AccessDeniedException when the current author is not authorized to use this API
     */
    public XWikiAuthService getMainAuthService() throws AccessDeniedException
    {
        checkWikiAdmin();

        XWikiContext xcontext = this.contextProvider.get();

        return xcontext.getWiki().getAuthService();
    }

    /**
     * Get the {@link XWikiAuthService} according to {@link XWiki#getAuthService()} and the component based
     * authentication service system.
     * 
     * @return the configured authentication service
     * @throws AccessDeniedException when the current author is not authorized to use this API
     * @throws XWikiException when failing to get the authentication service
     */
    public XWikiAuthService getAuthService() throws AccessDeniedException, XWikiException
    {
        XWikiAuthService mainAuthService = getMainAuthService();

        if (mainAuthService instanceof DefaultXWikiAuthServiceComponent) {
            return ((DefaultXWikiAuthServiceComponent) mainAuthService).getAuthService();
        }

        return mainAuthService;
    }

    /**
     * @return the authentication service class indicated in xwiki.cfg
     * @throws AccessDeniedException when the current author is not authorized to use this API
     */
    public String getConfiguredAuthClass() throws AccessDeniedException
    {
        checkWikiAdmin();

        return this.xwikicfg.getProperty("xwiki.authentication.authclass");
    }

    /**
     * Get all the available authentication services.
     * 
     * @return the available authentication services
     * @throws AccessDeniedException when the current author is not authorized to use this API
     * @throws ComponentLookupException when failing to looking the authentication services
     */
    public List<XWikiAuthService> getAuthServices() throws AccessDeniedException, ComponentLookupException
    {
        checkWikiAdmin();

        ComponentManager componentManager = this.componentManagerProvider.get();

        List<XWikiAuthService> authServices = new ArrayList<>();

        for (XWikiAuthService authService : componentManager
            .<XWikiAuthService>getInstanceList(XWikiAuthServiceComponent.class)) {
            if (!(authService instanceof DefaultXWikiAuthServiceComponent)) {
                authServices.add(authService);
            }
        }

        return authServices;
    }

    /**
     * Set the authentication service in the wiki configuration.
     * 
     * @param id the identifier of the authentication service
     * @throws AccessDeniedException when the current author is not authorized to use this API
     * @throws XWikiException when failing to get the authentication service
     */
    public void setAuthService(String id) throws AccessDeniedException, XWikiException
    {
        checkWikiAdmin();

        this.configuration.setAuthService(id);
    }
}
