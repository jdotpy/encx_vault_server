from django.conf.urls import include, url

from . import views
from . import doc_views
from . import user_views

urlpatterns = [
    url(r'^ping$', views.ping),

    # Users
    url(r'^users/new$', user_views.user_new),
    url(r'^users/init$', user_views.user_init),
    url(r'^user/(?P<user_name>[^/]*)$', user_views.user_operations),

    # Audit
    url(r'^audit/log$', doc_views.audit_log),

    # Doc
    url(r'^docs/query$', doc_views.doc_query),
    url(r'^docs/new$', doc_views.doc_create_version, {'update': False}),
    url(r'^doc/update$', doc_views.doc_create_version, {'update': True}),
    url(r'^doc/sanction$', doc_views.doc_sanction),
    url(r'^doc/meta$', doc_views.doc_read_meta),
    url(r'^doc/versions$', doc_views.doc_versions),
    url(r'^doc/remove-version$', doc_views.doc_remove_version),
    url(r'^doc/destroy$', doc_views.doc_destroy),
    url(r'^doc/data$', doc_views.doc_read_data),
]
