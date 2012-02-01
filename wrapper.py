# -*- test-case-name: twisted.web.test.test_httpauth -*-
# Copyright (c) 2008 Twisted Matrix Laboratories.
# See LICENSE for details.

"""
A guard implementation which supports multiple web-based authentication
schemes.

If method is get and no credentials present browser is directed to login form
If method is post credentials are checked and routed according to succes or failure
credential factory is used only to check scheme, in this use case 'cleartext' which \
is checked against a hidden form input declaring as much (i.e value="cleartext")
"""

from zope.interface import implements
from twisted.internet import defer
from twisted.python import log
from twisted.python.components import proxyForInterface
from twisted.web import resource, util
from twisted.web.error import ErrorPage
from twisted.cred import credentials, error


class UnauthorizedResource(resource.Resource):
    """
    TBD.
    """

    isLeaf = True

    def __init__(self):
        resource.Resource.__init__(self)
        self._finished = False

    def _requestFinished(self, reason):
        self._finished = True

    def _failed(self, reason):
        log.msg(reason.getErrorMessage())

    def render_GET(self, request):
        """
        Send WWW-Authenticate headers to the client.
        """

        request.notifyFinish().addErrback(self._requestFinished)
        log.msg('UnathorizedResource.render_GET')
        if not self._finished:
            return """<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN">
<html>
    <head>
        <title>LOG IN</title>
    </head>
    <body>
    <form action="/myapp/" enctype="application/x-www-form-urlencoded" method="POST">
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
      <input type="hidden" name="scheme" value="myapp">
    </form>
    </body>
</html>"""



class RootResource(resource.Resource):
    isLeaf = False

    def __init__(self, user):
        resource.Resource.__init__(self)
        self.user = user
        children = ()
        for childName, childResource in children:
            self.putChild(childName, childResource)

    def getChild(self, path, request):
        ##import pdb
        #pdb.set_trace()
        segments = request.postpath

        if not path:
            requestedResource = self
        elif segments and segments[-1] == 'authorized':
            requestedResource = AuthorizedResource(self.user)
        else:
            requestedResource = resource.Resource.getChild(self, path, request)
        return requestedResource

    def render_GET(self, request):
        return 'txWebAuth: That thing we did, that does that thing you wanted.'



class WebAuthSessionWrapper(resource.Resource):
    """
    Wrap a twisted.cred.portal, requiring authN/authZ via various providers.
    """

    isLeaf = False

    def __init__(self, portal, credentialFactories, *children):
        """
        Initialize a session wrapper.
        """
        resource.Resource.__init__(self)
        self._portal = portal
        self._credentialFactories = credentialFactories
        for path, child in children:
            self.putChild(path, child)

    def _authorizedResource(self, request):
        """
        Get the twisted.web.resource.IResource which the given request is
        authorized to receive.  If the proper credentials are present, the
        resource will be requested from the portal.
        """
        #import pdb; pdb.set_trace()
        authProvider = None
        session = request.getSession()
        if session.avatar is not None:
            return session.avatar
        else:
            userCredentials = credentials.Anonymous()
            if request.method == 'POST':
                authProvider = request.postpath[0]
                for credentialFactory in self._credentialFactories:
                    if credentialFactory.scheme == authProvider:
                        userCredentials = credentialFactory.decode(request)
                        break
            return util.DeferredResource(self._login(userCredentials, request))

    def _login(self, credentials, request):
        """
        Get the twisted.web.resource.IResource avatar for the given credentials.

        Returns a twisted.internet.defer.Deferred which will be called back with
        a twisted.web.resource.IResource avatar or which will errback if
        authentication fails.
        """

        d = self._portal.login(credentials, request, resource.IResource)
        d.addCallbacks(self._loginSucceeded, self._loginFailed)
        return d

    def _loginSucceeded(self, (interface, avatar, logout)):
        #import pdb
        #pdb.set_trace()
        return avatar

    def _loginFailed(self, result):
        """
        Handle login failure by presenting either another challenge (for
        expected authentication/authorization-related failures) or a server
        error page (for anything else).
        """
        errorMessage = result.getErrorMessage()
        if result.check(error.Unauthorized, error.LoginFailed):
            log.msg('txsocmob.cred.HTTPSessionWrapper._loginFailed: ' + errorMessage)
            return util.Redirect('/login')
        else:
            return resource.ErrorPage(500, 'Server error.', errorMessage)

    def render(self, request):
        """
        Find the twisted.web.resource.IResource avatar suitable for the given
        request, if possible, and render it.  Otherwise, perhaps render an error
        page requiring authorization or describing an internal server failure.
        """

        return self._authorizedResource(request).render(request)


    def getChild(self, path, request):
        """
        TBD.
        """

        # Don't consume any segments of the request - this class should be
        # transparent!

        log.msg('getChild: ' + path)
        request.postpath.insert(0, request.prepath.pop())
        return self._authorizedResource(request)
