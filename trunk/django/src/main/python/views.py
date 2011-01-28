import os
import os.path
import sys
import subprocess

from django import forms
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render_to_response
from django.template import RequestContext # avoid CSRF
from django.views.generic import list_detail

from gc3libs import Run, Application
import gc3libs.application.gamess as gamess
import gc3libs.application.rosetta as rosetta
import gc3libs.Default as Default
from   gc3libs.Exceptions import *
import gc3libs.core as core
import gc3libs.persistence
import gc3libs.utils as utils

from gridcertlib.decorators import certificate_required, gridproxy_required

import gc3portal

# gc3pie interface

@login_required
def gstat(request):
    jobs = list(gc3libs.list_jobs(request.user.username))
    
    sorted_jobs = sorted(jobs, key=lambda Job: int(Job.unique_token.split('.')[1]))

    for job in sorted_jobs:
        job['done'] = "Yes" if job.status == 5 else "No"
        job['color'] = {
            0: 'white',   # initial
            1: '#3CB371',   # finished
            2: '#FFD700',  # running
            3: '#FF4500',     # failed
            4: '#7FFFD4',  # ready
            5: '#ADFF2F', # completed
            6: 'red',     # aborted
            7: 'grey',    # undefined
            }[job.status]

    return render_to_response('jobs.html', {'job_list':sorted_jobs})


def run_command(cmdline):
    """
    Run `cmdline` through the shell and return standard output and
    error merged into one single string.
    """
    p = subprocess.Popen(cmdline, stdout=subprocess.PIPE, 
                         stderr=subprocess.STDOUT, shell=True)
    return p.communicate()[0]

@login_required
def list_available_resources(request):
    resources = gc3portal.glist()
    return render_to_response('resources.html', {'resource_list':resources})

@login_required
def list_jobs(request):
    jobs = gc3portal.list_jobs(None)

    if jobs:
        jobs = sorted(jobs, key=lambda Job: int(Job.unique_token.split('.')[1]))

        for job in jobs:
            job['done'] = "Yes" if job.status == 5 else "No"
            job['color'] = {
                0: 'white',   # initial
                1: '#3CB371',   # finished
                2: '#FFD700',  # running
                3: '#FF4500',     # failed
                4: '#7FFFD4',  # ready
                5: '#ADFF2F', # completed
                6: 'red',     # aborted
                7: 'grey',    # undefined
                }[job.status]

    return render_to_response('jobs.html', {'job_list':jobs})
    
@login_required
def welcome(request):
    username = request.user.username
    output = '<h1>Welcome, user %s</h1>' % username

    resources = gc3portal.glist()

    return HttpResponse(output)


@certificate_required
def cert_info(request):
    username = request.user.username
    output = '<h1>Welcome, user %s</h1>' % username

    certdir =  os.path.join(settings.GRIDCERTLIB_ROOT, username)
    if not os.path.exists(certdir):
        output += """<p>No certificate directory at '%s'.</p>""" % certdir
    else:
        usercert = os.path.join(certdir, "usercert.pem")
        if not os.path.exists(usercert):
            output += """<p>No user certificate at '%s'.</p>""" % usercert
        else:
            stdout = run_command('openssl x509 -noout -text -in "$X509_USER_CERT"')
            output += """
<p>
Running 'openssl x509 -noout -text -in "$X509_USER_CERT"' over 
the certificate file '%s' returns: <pre>%s</pre>
<p>
""" % (usercert, stdout)

    return HttpResponse(output)


@gridproxy_required
def proxy_info(request):
    username = request.user.username
    output = '<h1>Welcome, user %s</h1>' % username

    certdir =  os.path.join(settings.GRIDCERTLIB_ROOT, username)
    if not os.path.exists(certdir):
        output += """<p>No certificate directory at '%s'.</p>""" % certdir
    else:
        usercert = os.path.join(certdir, "usercert.pem")
        if not os.path.exists(usercert):
            output += """<p>No user certificate at '%s'.</p>""" % usercert
        else:
            stdout = run_command('openssl x509 -noout -text -in "$X509_USER_CERT"')
            output += """
<p>
Running 'openssl x509 -noout -text -in "$X509_USER_CERT"' over 
the certificate file '%s' returns: <pre>%s</pre>
<p>
""" % (usercert, stdout)
            
        userproxy = os.path.join(certdir, "userproxy.pem")
        if not os.path.exists(userproxy):
            output += """<p>No user proxy at '%s'.</p>""" % userproxy
        else:
            stdout = run_command('openssl x509 -noout -text -in "$X509_USER_PROXY"')
            output += """
<p>
Running 'openssl x509 -noout -text -in "$X509_USER_PROXY"' over 
the proxy file '%s' returns: <pre>%s</pre>
<p>
""" % (userproxy, stdout)

    return HttpResponse(output)
