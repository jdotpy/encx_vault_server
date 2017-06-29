from django.conf.urls import include, url

urlpatterns = [
    url(r'^', include('vault_web.urls')),
]
