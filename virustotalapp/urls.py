from django.urls import path
from .views import *

urlpatterns = [
    path('get_virustotal_report/', get_virustotal_report, name='get_virustotal_report'),
]
