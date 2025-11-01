from django.urls import path
from .views import *
from django.conf.urls.static import static

urlpatterns = [
    path('get_virustotal_report/', get_virustotal_report, name='get_virustotal_report'),
    # path('<str:endpoint_type>/<str:endpoint_value>/refresh/', refresh_data, name='refresh_data'),
    # path('<str:endpoint_type>/refresh/', refresh_data, name='refresh_data'),
    path('get_virustotal_report_data/', get_virustotal_report_data, name='get_virustotal_report_data'),
]  + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
