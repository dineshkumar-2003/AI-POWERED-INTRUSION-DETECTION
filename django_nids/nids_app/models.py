from django.db import models

class NetworkTraffic(models.Model):
    flow_duration = models.FloatField()
    flow_bytes_per_sec = models.FloatField()
    packet_length_variance = models.FloatField()
    bwd_packet_length_mean = models.FloatField()
    fwd_iat_mean = models.FloatField()
    init_win_bytes_forward = models.FloatField()
    subflow_fwd_packets = models.IntegerField()
    prediction = models.CharField(max_length=20)
    threat_percentage = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Traffic {self.id} - {self.prediction} ({self.threat_percentage}%)"
