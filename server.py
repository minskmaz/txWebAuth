from zope.interface import implements
from twisted.cred.portal import IRealm, Portal
from twisted.cred.checkers import FilePasswordDB
from twisted.web.static import File
from twisted.web.resource import IResource
from wrapper import XHTMLAuthSessionWrapper
from credfactory import FormCredentialFactory
import os
from twisted.web.resource import Resource
from twisted.application import service, internet
from twisted.web import static, server, resource




class XHMTLAuthenticatedRealm(object):
    implements(IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        if IResource in interfaces:
            return (IResource, File("/Users/%s/" % (avatarId,)), lambda: None)
        raise NotImplementedError()

portal = Portal(XHMTLAuthenticatedRealm(), [FilePasswordDB('httpd.password')])
credentialFactory = FormCredentialFactory("http://localhost:9000/")
authenticated_resource = XHTMLAuthSessionWrapper(portal, [credentialFactory])


root = Resource()
root.putChild("myapp", authenticated_resource)


def getWebService():
    """Return a service suitable for creating an application object. """
    return internet.TCPServer(9000, server.Site(root))

application = service.Application("FormAuthDemo")
service = getWebService()
service.setServiceParent(application)