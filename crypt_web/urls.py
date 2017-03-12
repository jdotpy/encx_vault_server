from django.conf.urls import include, url

from . import views

urlpatterns = [
    url(r'^$', views.home),
    url(r'^users/init$', views.user_init),
    url(r'^docs/query$', views.doc_query),
    url(r'^docs/new$', views.doc_new),
    url(r'^doc/meta$', views.doc_read_meta),
    url(r'^doc/versions$', views.doc_versions),
    url(r'^doc/remove-version$', views.doc_remove_version),
    url(r'^doc/destroy$', views.doc_destroy),
    url(r'^doc/data$', views.doc_read_data),
]
