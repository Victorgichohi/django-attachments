from django.conf.urls import patterns, url

urlpatterns = patterns('',
    url(r'^add-for/(?P<app_label>[\w\-]+)/(?P<model_name>[\w\-]+)/(?P<pk>\d+)/$', 'attachments.views.add_attachment', name="add_attachment"),
    url(r'^delete/(?P<attachment_pk>\d+)/$', 'attachments.views.delete_attachment', name="delete_attachment"),
)
