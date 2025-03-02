from django.urls import path
from .views import index, detect_intrusion,get_packet_data

urlpatterns = [
    path('', index, name='index'),
    path('api/detect_intrusion/', detect_intrusion, name='detect_intrusion'),
    path('get_packet_data/', get_packet_data, name='get_packet_data'),
]
