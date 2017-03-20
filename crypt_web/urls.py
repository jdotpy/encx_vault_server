from django.conf.urls import include, url

from . import views

urlpatterns = [
    url(r'^ping$', views.ping),
    url(r'^user$', views.user_get),
    url(r'^user/root$', views.user_get_root),
    url(r'^user/sign$', views.sign_user),
    url(r'^users/new$', views.user_new),
    url(r'^user/init$', views.user_init),
    url(r'^audit/log$', views.audit_log),
    url(r'^docs/query$', views.doc_query),
    url(r'^docs/new$', views.doc_create_version, {'update': False}),
    url(r'^doc/update$', views.doc_create_version, {'update': True}),
    url(r'^doc/sanction$', views.doc_sanction),
    url(r'^doc/meta$', views.doc_read_meta),
    url(r'^doc/versions$', views.doc_versions),
    url(r'^doc/remove-version$', views.doc_remove_version),
    url(r'^doc/destroy$', views.doc_destroy),
    url(r'^doc/data$', views.doc_read_data),
]
