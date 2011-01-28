from django.conf.urls.defaults import *
from django.conf import settings

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
                       # Example:
                           # (r'^gc3utils/', include('gc3utils.foo.urls')),
                       
		  	# std Django authentication code
    			(r'^login/*$', 'django.contrib.auth.views.login'),
    			(r'^logout/*$', 'django.contrib.auth.views.logout'),

                       # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
                       # to INSTALLED_APPS to enable admin documentation:
                           # (r'^admin/doc/', include('django.contrib.admindocs.urls')),
                       #(r'^mygamess/*$', 'GC3portal.portal.views.welcome'),
		       (r'^/*$', 'GC3portal.portal.views.welcome'),
                       (r'^resources/*$', 'GC3portal.portal.views.list_available_resources'),
		       (r'^cert-info/*$', 'GC3portal.portal.views.cert_info'),
		       (r'^proxy-info/*$', 'GC3portal.portal.views.proxy_info'),
                       #(r'^submit/*$',    'GC3portal.portal.views.submit'),
                       #(r'^get/(?P<job_id>job.\d+)/$', 'GC3portal.portal.views.retrieve'),
                       #(r'^info/(?P<job_id>job.\d+)/$', 'GC3portal.portal.views.detail'),
                       #(r'^results/(?P<path>.*)$', 'django.views.static.serve', {'document_root': '/home/sergio/results', 'show_indexes': True }),
                       #(r'^view/(?P<job_id>job.\d+)(?P<file_name>.*)$', 'GC3portal.portal.views.fileview'),
		       (r'^jobs/*$', 'GC3portal.portal.views.list_jobs'),
                       #(r'^gamess_out/(?P<path>.*)$', 'django.views.static.serve',{'document_root': "/home/sergio/results"}),
                       (r'^site_media/(?P<path>.*)$', 'django.views.static.serve',{'document_root': settings.STATIC_DOC_ROOT}),
                       # Uncomment the next line to enable the admin:
                           (r'^admin/', include(admin.site.urls)),
			#(r'*',		'django.contrib.auth.views.login'),
                        
                       # django-shibboleth
                       ('^' + settings.SHIB_ROOT + '/', include('django_shibboleth.urls')),
                )

