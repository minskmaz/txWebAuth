import os

from zope import interface

from twisted.application import internet, service
from twisted.cred import checkers, portal
from twisted.python import log
from twisted.web import resource, server, static

from txWebAuth import credfactory, wrapper



def logout():
    """
    A simple do-nothing placeholder for logout behavior.
    """

    log.msg('logout called.')
    return None



def sessionExpired(session):
    log.msg('session expired.')
    session.avatar = None



class WebAuthSession(server.Session):
    sessionTimeout = 3600

    def __init__(self, site, uid, reactor=None):
        server.Session.__init__(self, site, uid, reactor)
        self.avatar = None



class WebAuthenticatedRealm(object):
    interface.implements(portal.IRealm)

    def __init__(self, anonymousRoot, authorizedRoot):
        self.anonymousRoot = anonymousRoot
        self.authorizedRoot = authorizedRoot

    def requestAvatar(self, avatarId, request, *interfaces):
        """
        Called after the user has successfully authenticated, returning an
        IResource instance representing the user's HTTP interface to an app.
        """

        if resource.IResource in interfaces:
            session = request.getSession()
            if avatarId is checkers.ANONYMOUS:
                log.msg('Anonymous')
                return (resource.IResource, self.anonymousRoot(), logout)
            else:
                log.msg('Authenticated: ' + avatarId)
                avatar = self.authorizedRoot('/Users/%s' % (avatarId,))
                session.avatar = avatar
                if not session.expireCallbacks:
                    session.notifyOnExpire(lambda: sessionExpired(session))
                return (
                    resource.IResource,
                    avatar,
                    logout
                )
        log.msg('requestAvatar: Realm not implemented.')
        raise NotImplementedError()



credentialFactories = [credfactory.FormCredentialFactory("myapp")]

root = wrapper.WebAuthSessionWrapper(
    portal.Portal(
        WebAuthenticatedRealm(wrapper.UnauthorizedResource, static.File),
        [
            checkers.AllowAnonymousAccess(),
            checkers.InMemoryUsernamePasswordDatabaseDontUse(**{'admin': 'letmein', 'ldb': 'letmein'})
            #checkers.FilePasswordDB('httpd.password')
        ]
    ),
    credentialFactories
)


def getWebService():
    """Return a service suitable for creating an application object. """
    site = server.Site(root)
    site.sessionFactory = WebAuthSession
    return internet.TCPServer(9000, site)

application = service.Application("FormAuthDemo")
service = getWebService()
service.setServiceParent(application)
