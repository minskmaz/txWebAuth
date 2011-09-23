# -*- test-case-name: twisted.web.test.test_httpauth -*-
# Copyright (c) 2008 Twisted Matrix Laboratories.
# See LICENSE for details.

"""
A guard implementation which supports form-based authentication
schemes.

If method is get and no credentials present browser is directed to login form
If method is post credentials are checked and routed according to succes or failure
credential factory is used only to check scheme, in this use case 'cleartext' which \
is checked against a hidden form input declaring as much (i.e value="cleartext")
"""

from zope.interface import implements
from twisted.python import log
from twisted.python.components import proxyForInterface
from twisted.web.resource import IResource
from twisted.web import util
from twisted.web.error import ErrorPage
from twisted.cred import error as credError
from twisted.web._auth.wrapper import UnauthorizedResource


class XHTMLUnauthorizedResource(object):
    """
    Simple IResource to escape Resource dispatch
    """
    implements(IResource)
    isLeaf = True


    def __init__(self, factories):
        self._credentialFactories = factories


    def render(self, request):
        """
        Send www-authenticate headers to the client
        """
        
        session = request.getSession()
        
        login_form = """
        <!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN">
        <html>
        	<head>
        		<title>LOG IN</title>
        	</head>
        	<body>
        	<form action="" method="POST">
              <div class="row">
                <div class="label"><label for="login">Login</label></div>
                <div class="field">
                  <input type="text" name="login" id="login" value="admin" />
                </div>
              </div>

              <div class="row">
                <div class="label"><label for="password">Password</label></div>
                <div class="field">
                  <input type="password" name="password" id="password" value="letmein"/>
                </div>
              </div>

              <div class="row">
                <input class="form-element" type="submit" 
                       name="SUBMIT" value="Log in" />
              </div>
              <input type="hidden" name="camefrom" value="http://localhost:9000/login">
              <input type="hidden" name="scheme" value="cleartext">
            </form>
        	</body>
        </html>
        """
        
        return login_form

    def getChildWithDefault(self, path, request):
        """
        Disable resource dispatch
        """
        return self
        



        
class XHTMLAuthSessionWrapper(object):
    """
    Wrap a portal, enforcing supported header-based authentication schemes.

    @ivar _portal: The L{Portal} which will be used to retrieve L{IResource}
        avatars.

    @ivar _credentialFactories: A list of L{ICredentialFactory} providers which
        will be used to decode I{Authorization} headers into L{ICredentials}
        providers.
    """
    implements(IResource)
    isLeaf = False

    def __init__(self, portal, credentialFactories):
        """
        Initialize a session wrapper

        @type portal: C{Portal}
        @param portal: The portal that will authenticate the remote client

        @type credentialFactories: C{Iterable}
        @param credentialFactories: The portal that will authenticate the
            remote client based on one submitted C{ICredentialFactory}
        """
        self._portal = portal
        self._credentialFactories = credentialFactories


    def render(self, request):
        raise NotImplementedError


    def processLogin(self, path, request):
        """I process the login parameters"""


    def getChildWithDefault(self, path, request):
        """
        Inspect headers for method and route accordingly to either login form
        or credential checker
        """
        method = request.method


        if method == 'POST':
            print "METHOD IS POST"
            "The login form has been submitted so process the credentials"
            args = request.args
            scheme = args['scheme'][0] 
            for fact in self._credentialFactories:
                if fact.scheme == scheme:
                    try:
                        credentials = fact.decode(request)
                    except credError.LoginFailed:
                        return UnauthorizedResource(self._credentialFactories)
                    except:
                        log.err(None, "Unexpected failure from credentials factory")
                        return ErrorPage(500, None, None)
                    else:
                        print "WE ARE GOOD TO GO"
                        return util.DeferredResource(self._login(credentials))
                else:
                    return XHTMLUnauthorizedResource(self._credentialFactories) 
        else:
            "Direct user to a login form"
            return XHTMLUnauthorizedResource(self._credentialFactories)


    def _login(self, credentials):
        """
        Get the L{IResource} avatar for the given credentials.

        @return: A L{Deferred} which will be called back with an L{IResource}
            avatar or which will errback if authentication fails.
        """

        d = self._portal.login(credentials, None, IResource)
        d.addCallbacks(self._loginSucceeded, self._loginFailed)
        return d


    def _loginSucceeded(self, (interface, avatar, logout)):
        """
        Handle login success by wrapping the resulting L{IResource} avatar
        so that the C{logout} callback will be invoked when rendering is
        complete.
        """
        
        print "LOGIN SUCCEEDED"
        
        class ResourceWrapper(proxyForInterface(IResource, 'resource')):
            """
            Wrap an L{IResource} so that whenever it or a child of it
            completes rendering, the cred logout hook will be invoked.

            An assumption is made here that exactly one L{IResource} from
            among C{avatar} and all of its children will be rendered.  If
            more than one is rendered, C{logout} will be invoked multiple
            times and probably earlier than desired.
            """
            def getChildWithDefault(self, name, request):
                """
                Pass through the lookup to the wrapped resource, wrapping
                the result in L{ResourceWrapper} to ensure C{logout} is
                called when rendering of the child is complete.
                """
                return ResourceWrapper(self.resource.getChildWithDefault(name, request))

            def render(self, request):
                """
                Hook into response generation so that when rendering has
                finished completely, C{logout} is called.
                """
                request.notifyFinish().addCallback(lambda ign: logout())
                return super(ResourceWrapper, self).render(request)

        return ResourceWrapper(avatar)


    def _loginFailed(self, result):
        """
        Handle login failure by presenting either another challenge (for
        expected authentication/authorization-related failures) or a server
        error page (for anything else).
        """
        print "LOGIN FAILED"
        if result.check(credError.Unauthorized, credError.LoginFailed):
            return UnauthorizedResource(self._credentialFactories)
        else:
            log.err(
                result,
                "HTTPAuthSessionWrapper.getChildWithDefault encountered "
                "unexpected error")
            return ErrorPage(500, None, None)
