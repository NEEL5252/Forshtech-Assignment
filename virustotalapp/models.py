from django.db import models

# Create your models here.
class VirusTotalReport(models.Model):
    endpoint_type = models.CharField(max_length=50)
    endpoint_value = models.CharField(max_length=255, null=True, blank=True)
    file_scan = models.FileField(upload_to='uploads/', null=True, blank=True)
    full_data = models.JSONField(null=True, blank=True)


    def __str__(self):
        return str(self.pk) + " :- " + str(self.endpoint_type) + " - " + str(self.endpoint_value)