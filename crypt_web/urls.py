from django.conf.urls import include, url

from . import views

urlpatterns = [
    url(r'^$', views.home),
    url(r'^init-user$', views.user_init),
    url(r'^query$', views.query),
    url(r'^new$', views.new),
    url(r'^document$', views.read),
    url(r'^document/data$', views.read_data),
]
