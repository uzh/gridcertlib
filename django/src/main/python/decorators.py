#! /usr/bin/env python
#
"""
Decorators for a Grid portal views.

This file provides two decorators, `certificate_required` and
`proxy_required`, that work just like the Django std `login_required`
decorator, but check that the user accessing the view has a valid
certificate (resp. Grid proxy) and redirect to the relevant
GridCertLib servlet if not.
"""
__docformat__ = 'reStructuredText'

import os
import os.path
import random
import time
import types
import urllib

try:
    from functools import update_wrapper, wraps
except ImportError:
    from django.utils.functional import update_wrapper, wraps  # Python 2.4 fallback.

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.utils.http import urlquote


_random = random.SystemRandom()

def _make_random_string(bits=128):
    return ("%x" % _random.getrandbits(bits))


def _make_url(*paths, **kw):
    """
    Return URL formed by appending path components and query
    parameters.  The resulting URL is formed by joining all items in
    `paths` with a ``/`` character, then appending each keyword
    argument as a query parameter.

    Example::

      >>> _make_url("http://www.example.com", "foo")
      'http://www.example.com/foo'

      >>> _make_url("http://www.example.org", bar=1)
      'http://www.example.org?bar=1'

      >>> _make_url("http://google.com/", "/search", q="gridcertlib")
      'http://google.com/search?q=gridcertlib'

      >>> _make_url("http://localhost", "gridcertlib", "voms-proxy-init", 
      ...           vo=['smscg', 'life'])
      'http://localhost/gridcertlib/voms-proxy-init?vo=smscg&vo=life'

    As a special case, query parameters can be added to an
    already-formed URL::

      >>> _make_url("http://google.com/search?q=gridcertlib", hl='en')
      'http://google.com/search?q=gridcertlib&hl=en'
    """
    def strip_slashes(p):
        while p.startswith('/'):
            p = p[1:]
        while p.endswith('/'):
            p = p[:-1]
        return p
    paths = [ strip_slashes(p) for p in paths ]
    url = str.join('/', paths)

    def seq_of_query_pairs(D):
        for k, v in D.items():
            if type(v) in types.StringTypes:
                yield (k, v)
            else:
                try:
                    # is `v` a sequence?
                    for m in v:
                        yield (k, m)
                except:
                    # no, use its string representation
                    yield (k, v)
    query = urllib.urlencode(list(seq_of_query_pairs(kw)), False)
    if len(query) > 0:
        if '?' in url:
            return "%s&%s" % (url, query)
        else:
            return "%s?%s" % (url, query)
    else:
        return url
        

def _modified_recently(path, timediff):
    """
    Return `True` if the specified file exists and was modified in the
    last `timediff` seconds. Otherwise, return `False`.
    """
    try:
        mtime = os.stat(path).st_mtime
        now = int(time.time())
        return (now - mtime) < timediff
    except OSError, ex:
        if ex.errno == 2: # file not found
            return False
        else:
            raise


def _gridcertlib_required(view_fn, test_fn, next_url):
    """
    Return a decorator for views that checks that the user passes the
    given test function; if not, issues an HTTP redirect to the
    specified `next_url`.  Assuming `next_url` points to a GridCertLib
    servlet, sets up the environment to make a successful call.
    """
    @wraps(view_fn)
    def wrapper(request, *args, **kw):
        if not request.session.has_key('GridCertLib.sessionId'):
            request.session['GridCertLib.sessionId'] = _make_random_string()
        session_id = request.session['GridCertLib.sessionId']

        # ensure the private key password is stored in the session
        #if not request.session.has_key('GridCertLib.privateKeyPassword'):
        #    request.session['GridCertLib.privateKeyPassword'] = User.objects.make_random_password(32)
        request.session['GridCertLib.privateKeyPassword'] = 'xG3FSfBZUFFb2CwX9KZTxQ7XdPjZeSJn'

        certdir =  os.path.join(settings.GRIDCERTLIB_ROOT, request.user.username)
        if not os.path.exists(certdir):
            os.mkdir(certdir)

        # get the Shibboleth session ID from HTTP headers; use it to
        # create a marker file in the chosen usercert directory
        marker = os.path.join(certdir, "SESSION." + session_id)
        open(marker, 'w+b').close()

        if test_fn(certdir):
            return view_fn(request, *args, **kw)
        else:
            # redirect to GridCertLib servlet
            self_url = urlquote(request.build_absolute_uri())
            response = HttpResponseRedirect(_make_url(next_url, 
                                                      key=session_id, 
                                                      store=certdir, 
                                                      next=self_url))
            response.set_cookie('GridCertLib.privateKeyPassword',
                                request.session['GridCertLib.privateKeyPassword'])
            return response
    return wrapper


def certificate_required(view_fn,
                         slcsinit_url=None,
                         redirect_field_name=REDIRECT_FIELD_NAME):
    """
    Decorator for views that checks that user has a valid X.509
    certificate, redirecting to the GridCertLib ``SlcsInit`` servlet
    (at `slcsinit_url`) if necessary.
    
    Chain-calls the `login_required` decorator as a side-effect;
    optional argument `redirect_field_name` is passed on to the
    `login_required` invocation.
    """
    if slcsinit_url is None:
        slcsinit_url = settings.GRIDCERTLIB_SLCSINIT_URL
    slcsinit_url = _make_url(slcsinit_url, )

    def usercert_is_valid(certdir):
        # XXX: instead of actually verifying that the certificate is
        # valid, we assume that:
        #   1. all certificates are created with the same duration (11 days)
        #   2. if a certificate exists, it at least *was* a valid
        #      certificate and thus only check the last modification time
        #      (i.e., last time the *content* was modified)
        usercert = os.path.join(certdir, 'usercert.pem')
        valid = _modified_recently(usercert, 10*24*3600) # less than 10 days ago
        if valid:
            os.environ["X509_USER_CERT"] = usercert
            os.environ["X509_USER_KEY"] = os.path.join(certdir, 'userkey.pem')
        return valid

    wrapper = _gridcertlib_required(view_fn, usercert_is_valid, slcsinit_url)
    # the `wrapper` above needs to access user data, so the actual
    # decorator is a chain of `login_required` *followed* by the above
    # `wrapper`
    return login_required(wrapper, 
                          redirect_field_name=redirect_field_name)


def gridproxy_required(view_fn,
                       proxyinit_url=None,
                       redirect_field_name=REDIRECT_FIELD_NAME):
    """
    Decorator for views that checks that user has a valid Grid proxy,
    redirecting to the GridCertLib ``VomsProxyInit`` servlet if
    necessary.
    
    Chain-calls the `certificate_required` decorator, to which the 
    optional `redirect_field_name` argument is passed unchanged.
    """
    if proxyinit_url is None:
        proxyinit_url = settings.GRIDCERTLIB_PROXYINIT_URL
    # FIXME: hard-coded value!
    proxyinit_url = _make_url(proxyinit_url, vo='smscg')

    def userproxy_is_valid(certdir):
        # XXX: instead of actually verifying that the proxy is
        # valid, we assume that:
        #   1. all proxies are created with the same duration (12 hours)
        #   2. if a proxy exists, it at least *was* a valid
        #      proxy and thus only check the last modification time
        #      (i.e., last time the *content* was modified)
        userproxy = os.path.join(certdir, 'userproxy.pem')
        valid = _modified_recently(userproxy, 11*3600) # less than 11 hours ago
        if valid:
            os.environ["X509_USER_PROXY"] = userproxy
        return valid

    wrapper = _gridcertlib_required(view_fn, userproxy_is_valid, proxyinit_url)
    # the `wrapper` above needs to access user data and the
    # certificate, so the actual decorator is a chain of
    # `certificate_required` *followed* by the above `wrapper`
    return certificate_required(wrapper, 
                                redirect_field_name=redirect_field_name)



## main: run tests

if "__main__" == __name__:
    import doctest
    doctest.testmod(name="decorators",
                    optionflags=doctest.NORMALIZE_WHITESPACE)
